// Rendered integration of the real App and CSV import workspace. Every API response
// is an in-memory fixture; no product backend, database or shared identity is used.
// Run: node web-ui/src/DataLoad.browser.mjs [result.json]
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
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
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-import-review-"));
const server = await createServer({
  root: webRoot,
  cacheDir,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
});
const application = {
  workspaceId: "fixture",
  applicationId: "import",
  name: "Import fixture",
  status: "Active",
  kind: "blank",
};
const inputRejections = {
  format: "openepm-csv-input-rejections-v1",
  phase: "before_chunk_write",
  httpStatus: 400,
  firstDispatchOnly: true,
  priorUncertainty: "retain_original",
  changedInput: "new_admission",
  codes: ["SOURCE_AMOUNT_INVALID"],
};
const batchId = "b".repeat(32),
  digest = "d".repeat(64),
  requestId = "1".repeat(32);
const catalog = {
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    issuer: "fixture",
    subjectId: "operator",
  },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    [
      "facts.source.begin",
      "facts.source.csv.append",
      "facts.source.seal",
      "facts.source.manifest.attach",
      "facts.source.preview",
      "facts.source.staging.read",
      "facts.transfer.import.request",
      "facts.transfer.import.read",
      "application.operation.receipt.read",
    ].map((name) => [name, {}]),
  ),
  revisions: { metadata: 7, data: 9, policy: 1, security: 1, commit: 12 },
};
catalog.functions["facts.source.csv.append"] = { inputRejections };
const sourcePaths = [
  "DataLoad.tsx",
  "data-transfer-action.ts",
  "data-workspaces.css",
  "ImportChangeReview.tsx",
  "ReceiptInspector.tsx",
  "api.ts",
  "App.tsx",
  "CapabilityArea.tsx",
  "unsaved-work.ts",
  "DataLoad.browser.mjs",
];
const sourceManifest = async () =>
  Promise.all(
    sourcePaths.map(async (name) => ({
      path: "web-ui/src/" + name,
      sha256: createHash("sha256")
        .update(await readFile(resolve(webRoot, "src", name)))
        .digest("hex"),
    })),
  );
const capturedSource = await sourceManifest();
const report = {
  startedAt: new Date().toISOString(),
  sourceFiles: capturedSource,
  method:
    "Real Chromium App/CapabilityArea/DataLoad; all API calls intercepted with isolated in-memory fixtures. No server publication claimed.",
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
  for (const width of [650, 1280]) {
    const context = await browser.newContext({
      viewport: { width, height: 1000 },
    });
    const page = await context.newPage();
    page.on("pageerror", (error) => report.pageErrors.push(error.message));
    let admissionCount = 0,
      publicationAdmissions = 0;
    const publications = [];
    const staging = [];
    const stagingReads = [];
    const previews = [];
    const reads = [];
    const receiptReads = [];
    const pausedStage = pauseResponse();
    const pausedRecovery = pauseResponse();
    const pausedPreview = pauseResponse();
    const pausedPublication = pauseResponse();
    const pausedStatus = pauseResponse();
    const pausedReceiptDenial = pauseResponse();
    const lostStage =
      width === 650
        ? "facts.source.csv.append"
        : "facts.source.manifest.attach";
    const withCorrection = width === 1280;
    let lostStaging = false;
    let clockOffsetMs = 0;
    let securityRevision = 1;
    let refusePreviewForAccess = false;
    const previewAccessMessage =
      "Access changed while preparing the import preview. Refresh the application and preview again under current access.";
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
      if (path === "/api/catalog")
        return route.fulfill(
          json({
            ...catalog,
            revisions: { ...catalog.revisions, security: securityRevision },
          }),
        );
      if (
        path === "/api/read" &&
        body?.program?.function === "application.operation.receipt.read"
      ) {
        receiptReads.push({ securityRevision, body });
        if (securityRevision === 2) {
          await pausedReceiptDenial.hold();
          return route.fulfill(
            json(
              {
                code: "APPLICATION_GRANT_REQUIRED",
                message: "private outcome detail",
              },
              403,
            ),
          );
        }
        return route.fulfill(
          json({
            result: {
              operationId: batchId,
              actorId: "fixture-publisher",
              commandDigest: "a".repeat(64),
              committedRevision: 13,
              committedAt: "2026-11-19T00:00:00Z",
              outcome: {
                setCount: securityRevision === 1 ? 501 : 702,
                batchId,
              },
            },
          }),
        );
      }
      if (path === "/api/tasks")
        return route.fulfill(
          json({ tasks: [], nextSequence: 0, hasMore: false }),
        );
      if (path === "/api/operation-admission") {
        admissionCount++;
        if (body.program.function === "facts.transfer.import.request")
          publicationAdmissions++;
        return route.fulfill(
          json({
            operationId: `oa1_zz_${admissionCount.toString(16).repeat(32)}_${"A".repeat(43)}`,
            expiresAt: Math.floor((Date.now() + clockOffsetMs) / 1000) + 900,
            intentDigest: "a".repeat(64),
          }),
        );
      }
      if (path === "/api/source-load") {
        const status = body.program.function === "facts.source.staging.read";
        const original = status
          ? staging.find(
              (packet) =>
                packet.idempotencyKey === body.program.arguments.operationId,
            )
          : body;
        if (status) {
          assert.deepEqual(
            body.program.arguments.originalProgram,
            original.program,
          );
          assert.equal(body.idempotencyKey, undefined);
          stagingReads.push(body);
          await pausedRecovery.hold();
        }
        const fn = original.program.function;
        if (
          !status &&
          [
            "facts.source.begin",
            "facts.source.csv.append",
            "facts.source.seal",
            "facts.source.manifest.attach",
          ].includes(fn)
        ) {
          staging.push(body);
          if (
            fn === "facts.source.csv.append" &&
            body.program.arguments.csvText.includes(",wrong,")
          )
            return route.fulfill(json({ error: "SOURCE_AMOUNT_INVALID" }, 400));
          if (fn === lostStage && !lostStaging) {
            lostStaging = true;
            return route.abort("connectionreset");
          }
        }
        let result;
        if (fn === "facts.source.begin") {
          await pausedStage.hold();
          result = {
            batchId,
            status: "staging",
            rowCount: 0,
            contentDigest: digest,
            duplicate: false,
          };
        } else if (fn === "facts.source.csv.append")
          result = {
            batchId,
            chunkIndex: 0,
            rowCount: 3,
            contentDigest: digest,
            duplicate: false,
          };
        else if (fn === "facts.source.seal")
          result = {
            batchId,
            status: "ready",
            rowCount: 3,
            contentDigest: digest,
          };
        else if (fn === "facts.source.manifest.attach")
          result = {
            batchId,
            requestKey: original.idempotencyKey,
            schemaVersion: "openepm.typed-csv.v1",
            contentDigest: digest,
            manifestDigest: "e".repeat(64),
          };
        else if (fn === "facts.source.preview") {
          previews.push(body);
          if (refusePreviewForAccess) {
            return route.fulfill(
              json(
                {
                  code: "SOURCE_PREVIEW_AUTHORIZATION_STALE",
                  message: previewAccessMessage,
                  details: {},
                },
                409,
              ),
            );
          }
          await pausedPreview.hold();
          result = {
            batchId,
            contentDigest: digest,
            previewToken: "original-review",
            setCount: 3,
            clearCount: 0,
            review: {
              format: "openepm-source-change-review-v1",
              mode: "merge",
              scopeMembers: {},
              scopeAll: true,
              periodSelection: null,
              metadataRevision: 7,
              dataRevision: 9,
              commitRevision: 12,
              sampleLimitPerAction: 20,
              setsComplete: true,
              clearsComplete: true,
              readRestricted: false,
              examples: [
                {
                  action: "set",
                  members: { Account: "Revenue" },
                  valueKind: "numeric",
                  sourceRef: "row1",
                  before: { present: false },
                  after: { present: true, amount: "0.00000000" },
                },
                {
                  action: "set",
                  members: { Account: "Comment" },
                  valueKind: "text",
                  sourceRef: "row2",
                  before: { present: false },
                  after: { present: true, text: "" },
                },
                {
                  action: "set",
                  members: { Account: "Cost" },
                  valueKind: "detail",
                  sourceRef: "row3",
                  before: { present: false },
                  after: {
                    present: true,
                    amount: "100.00000001",
                    items: [{ description: "Travel", amount: "100.00000001" }],
                  },
                },
              ],
            },
          };
          if (previews.length === 1) {
            if (width === 650) {
              result.setCount = 4;
              result.review.setsComplete = false;
            } else {
              result.review.examples[0].members = { FormerAccount: "Revenue" };
            }
          }
        } else if (fn === "facts.transfer.import.request") {
          publications.push(body);
          assert.equal(publications.length, 1);
          await pausedPublication.hold();
          return route.abort("connectionreset");
        } else if (
          fn === "facts.transfer.import.read" &&
          body.program.arguments.operationId
        ) {
          assert.deepEqual(body.program.arguments, {
            operationId: publications[0].idempotencyKey,
          });
          result = {
            requestId,
            batchId,
            status: "Accepted",
            claimGeneration: 0,
            cancelRequested: false,
            result: null,
            errorCode: null,
          };
        } else if (fn === "facts.transfer.import.read") {
          reads.push(body);
          await pausedStatus.hold();
          result = {
            requestId,
            batchId,
            status: "Completed",
            claimGeneration: 1,
            cancelRequested: false,
            errorCode: null,
            result: {
              batchId,
              mode: "merge",
              setCount: 3,
              clearCount: 0,
              changedCount: 3,
              committedRevision: 13,
              contentDigest: digest,
            },
          };
        } else {
          report.unknownApi.push({ path, fn });
          return route.fulfill(json({ error: "FIXTURE_UNAVAILABLE" }, 400));
        }
        return route.fulfill(
          json({
            result: status ? { originalFunction: fn, outcome: result } : result,
          }),
        );
      }
      report.unknownApi.push({ path, fn: body?.program?.function });
      return route.fulfill(json({ error: "FIXTURE_UNAVAILABLE" }, 400));
    });
    await page.goto(
      base + "/#/data?section=import&workspace=fixture&application=import",
    );
    await page
      .getByRole("heading", { name: "Load governed CSV data" })
      .waitFor();
    const validCsv =
      'axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,0.00000000,row1\nComment,TextLiteral,,row2\nCost,LineDetailLiteral,"[{""description"":""Travel"",""decimal"":""100.00000001""}]",row3';
    await page
      .getByLabel("UTF-8 CSV text")
      .fill(
        withCorrection ? validCsv.replace("0.00000000", "wrong") : validCsv,
      );
    await page.getByRole("button", { name: "Prepare pasted CSV" }).click();
    await page.getByText(/Prepared \d+ bytes/).waitFor();
    await page.getByLabel("Whole application scope").check();
    await page
      .getByLabel("I reviewed the exact input and target scope")
      .check();
    const observedStates = [];
    const inspectPending = async (action, expected, count, paused) => {
      const origin = await action.elementHandle();
      await action.press("Enter");
      await paused.requested;
      const badge = page.locator(".data-load-journey .task-state");
      const observation = {
        focused: await origin.evaluate(
          (node) => document.activeElement === node,
        ),
        liveStatus: (await badge.getAttribute("role")) === "status",
        message: await badge.innerText(),
      };
      report.pendingObservation = observation;
      assert.deepEqual(observation, {
        focused: true,
        liveStatus: true,
        message: expected,
      });
      const before = count();
      await page.keyboard.press("Enter");
      assert.equal(count(), before);
      paused.release();
      observedStates.push(observation);
      delete report.pendingObservation;
      return origin;
    };
    await inspectPending(
      page.getByRole("button", { name: "Stage and validate CSV" }),
      "Staging CSV…",
      () => staging.length,
      pausedStage,
    );
    if (withCorrection) {
      await page
        .getByText("CSV correction required", { exact: true })
        .waitFor();
      const rejected = page.getByRole("textbox", {
        name: "Rejected and remaining CSV",
      });
      await rejected.waitFor();
      assert.match(
        await rejected.evaluate(
          (field) =>
            document.getElementById(field.getAttribute("aria-describedby"))
              ?.textContent,
        ),
        /SOURCE_AMOUNT_INVALID/,
      );
      await rejected.fill(validCsv);
      const correction = page.getByRole("button", {
        name: "Review corrected remainder",
      });
      const origin = await correction.elementHandle();
      await correction.press("Enter");
      await page
        .getByText("Staging ready to continue", { exact: true })
        .waitFor();
      assert.equal(
        await origin.evaluate((node) => document.activeElement === node),
        true,
      );
      assert.equal(await correction.isDisabled(), true);
      assert.equal(staging.length, 2);
      observedStates.push({
        focused: true,
        liveStatus: true,
        message: "CSV correction reviewed",
      });
      await page
        .getByRole("button", { name: "Continue original staging" })
        .press("Enter");
    }
    await page
      .getByRole("button", { name: "Retry connection", exact: true })
      .waitFor();
    clockOffsetMs += 3600_000;
    await page.evaluate(() => {
      const now = Date.now();
      Date.now = () => now + 3600_000;
    });
    await page
      .getByRole("button", { name: "Retry connection", exact: true })
      .click();
    const stagedRecovery = await inspectPending(
      page.getByRole("button", { name: "Check original staging status" }),
      "Checking the original staging step…",
      () => stagingReads.length,
      pausedRecovery,
    );
    const stagedStatus =
      lostStage === "facts.source.manifest.attach"
        ? "Staging complete"
        : "Staging ready to continue";
    await page.getByText(stagedStatus, { exact: true }).waitFor();
    assert.equal(
      await stagedRecovery.evaluate((node) => document.activeElement === node),
      true,
    );
    assert.equal(await stagedRecovery.getAttribute("aria-disabled"), "true");
    if (lostStage !== "facts.source.manifest.attach")
      await page
        .getByRole("button", { name: "Continue original staging" })
        .press("Enter");
    await page.getByRole("button", { name: "Preview exact changes" }).waitFor();
    const submitted = staging.filter(
      (body) => body.program.function === lostStage,
    );
    assert.equal(submitted.length, 1);
    assert.equal(stagingReads.length, 1);
    assert.deepEqual(stagingReads[0].program.arguments, {
      operationId: submitted[0].idempotencyKey,
      originalProgram: submitted[0].program,
    });
    assert.equal(
      staging.filter((body) => body.program.function === "facts.source.begin")
        .length,
      1,
    );
    const stageAdmissions = withCorrection ? 5 : 4;
    assert.equal(admissionCount, stageAdmissions);
    if (withCorrection) {
      const [denied, continued] = staging.filter(
        (body) => body.program.function === "facts.source.csv.append",
      );
      assert.notEqual(denied.idempotencyKey, continued.idempotencyKey);
      assert.equal(
        denied.program.arguments.batchId,
        continued.program.arguments.batchId,
      );
    }
    assert.equal(await page.getByLabel("UTF-8 CSV text").isDisabled(), true);
    const previewAction = await inspectPending(
      page.getByRole("button", { name: "Preview exact changes" }),
      "Checking exact import changes…",
      () => previews.length,
      pausedPreview,
    );
    const previewFault =
      width === 650
        ? "The preview set count does not match the sealed row count."
        : "A change example does not match the reviewed fact dimensions.";
    await page.getByRole("alert").filter({ hasText: previewFault }).waitFor();
    assert.equal(
      await page
        .getByRole("region", { name: "Import change examples" })
        .count(),
      0,
    );
    assert.equal(
      await page
        .getByRole("button", { name: "Start durable publication" })
        .getAttribute("aria-disabled"),
      "true",
    );
    assert.equal(previews.length, 1);
    assert.equal(publications.length, 0);
    await previewAction.press("Enter");
    await page.getByText("Empty text (present)", { exact: true }).waitFor();
    assert.equal(previews.length, 2);
    assert.deepEqual(previews[0], previews[1]);
    assert.equal(
      staging.filter(({ program }) => program.function === "facts.source.seal")
        .length,
      1,
    );
    assert.equal(
      await previewAction.evaluate((node) => document.activeElement === node),
      true,
    );
    assert.equal(
      await page.getByText("0.00000000", { exact: true }).count(),
      1,
    );
    assert.equal(await page.getByText("Absent", { exact: true }).count(), 3);
    await page.getByText("Supporting detail items", { exact: true }).click();
    assert.equal(
      await page.getByText("Travel: 100.00000001", { exact: true }).isVisible(),
      true,
    );
    refusePreviewForAccess = true;
    await previewAction.press("Enter");
    await page
      .getByRole("alert")
      .filter({ hasText: previewAccessMessage })
      .waitFor();
    assert.equal(
      await page
        .getByRole("region", { name: "Import change examples" })
        .count(),
      0,
    );
    assert.equal(
      await page
        .getByRole("button", { name: "Start durable publication" })
        .getAttribute("aria-disabled"),
      "true",
    );
    assert.equal(publications.length, 0);
    assert.equal(previews.length, 3);
    refusePreviewForAccess = false;
    await previewAction.press("Enter");
    await page.getByText("Empty text (present)", { exact: true }).waitFor();
    assert.equal(previews.length, 4);
    assert.deepEqual(previews[2], previews[3]);
    assert.equal(
      staging.filter(({ program }) => program.function === "facts.source.seal")
        .length,
      1,
    );
    assert.equal(
      await page
        .getByRole("button", { name: "Start durable publication" })
        .isEnabled(),
      false,
    );
    await page.getByLabel("I reviewed the exact set and clear counts").check();
    await inspectPending(
      page.getByRole("button", { name: "Start durable publication" }),
      "Submitting publication request…",
      () => publications.length,
      pausedPublication,
    );
    await page
      .getByText("Publication outcome unknown", { exact: true })
      .waitFor();
    assert.equal(await page.getByLabel("UTF-8 CSV text").isDisabled(), true);
    // Advance the simulated admission clocks without waiting or creating a new intent.
    clockOffsetMs += 3600_000;
    await page.evaluate(() => {
      const now = Date.now();
      Date.now = () => now + 3600_000;
    });
    await page
      .getByRole("button", { name: "Retry connection", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Check original publication status" })
      .click();
    await page.getByText("Import accepted", { exact: true }).waitFor();
    assert.equal(publicationAdmissions, 1);
    assert.equal(publications.length, 1);
    const statusAction = await inspectPending(
      page.getByRole("button", { name: "Refresh", exact: true }),
      "Checking publication status…",
      () => reads.length,
      pausedStatus,
    );
    await page.getByText("Import completed", { exact: true }).waitFor();
    assert.equal(
      await statusAction.evaluate((node) => document.activeElement === node),
      true,
    );
    const openReceipt = page.getByRole("button", {
      name: "View publication outcome",
    });
    await openReceipt.press("Enter");
    const inspector = page.locator(".receipt-inspector");
    await inspector.getByText("501", { exact: true }).waitFor();
    const receiptHeading = inspector.getByRole("heading", {
      name: "Activity outcome",
    });
    assert.equal(
      await receiptHeading.evaluate((node) => node === document.activeElement),
      true,
    );
    const revalidate = async (revision) => {
      securityRevision = revision;
      await page.evaluate(() => window.dispatchEvent(new Event("online")));
    };
    await revalidate(2);
    await pausedReceiptDenial.requested;
    await inspector.getByText("Reading outcome…", { exact: true }).waitFor();
    assert.equal(await inspector.getByText("501", { exact: true }).count(), 0);
    pausedReceiptDenial.release();
    await inspector
      .getByRole("alert")
      .filter({ hasText: "Current access does not allow" })
      .waitFor();
    assert.equal(
      await inspector
        .getByText(/private outcome detail|fixture-publisher|501/)
        .count(),
      0,
    );
    await revalidate(3);
    await inspector.getByText("702", { exact: true }).waitFor();
    assert.equal(await inspector.getByRole("alert").count(), 0);
    await inspector.getByRole("button", { name: "Close" }).press("Enter");
    assert.equal(
      await openReceipt.evaluate((node) => node === document.activeElement),
      true,
    );
    // The Vite development app mounts each new read under React StrictMode.
    const attemptsPerRevision = [1, 2, 3].map(
      (revision) =>
        receiptReads.filter((read) => read.securityRevision === revision)
          .length,
    );
    assert.ok(attemptsPerRevision.every((count) => count >= 1 && count <= 2));
    for (const { body } of receiptReads) {
      assert.deepEqual(body, {
        workspaceId: "fixture",
        applicationId: "import",
        program: {
          languageVersion: 2,
          function: "application.operation.receipt.read",
          arguments: { operationId: batchId },
        },
      });
    }
    report.cases.push({
      width,
      exactPresenceAndDetail: "passed",
      explicitReviewGate: "passed",
      invalidPreviewPreservedSealedInput: previewFault,
      stagingReplay: {
        lostStep: lostStage,
        exactOriginalPacket: "passed",
        beginCount: 1,
        stageAdmissions,
        rejectedInputCorrected: withCorrection,
        inputFrozenUntilPublication: "passed",
      },
      originalStatusReadAfterClientExpiry: "passed",
      acceptedToCompleted: "passed",
      publicationAdmissions,
      observedStates,
      previewAuthorization: {
        oldExamplesCleared: true,
        publicationRemainedDisabled: true,
        freshPreviewKeptSealedBatch: true,
      },
      outcomeRevalidation: {
        clearedWhileReading: true,
        currentDenialWithoutPriorDetails: true,
        regrantLoadsNewOutcome: true,
        exactScopedReadAttempts: attemptsPerRevision,
        focusReturnedToOrigin: true,
      },
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
