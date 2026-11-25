// Actual current rule/calculated-member/source lifecycle components in Chromium.
// Native-shaped API responses and the code-display widget are isolated fixtures.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
let playwright;
try {
  playwright = require("playwright");
} catch {
  playwright = require(
    resolve(
      execFileSync("npm", ["root", "--global"], { encoding: "utf8" }).trim(),
      "playwright",
    ),
  );
}
const { createServer } = await import(
  resolve(webRoot, "node_modules/vite/dist/node/index.js")
);
const cacheDir = await mkdtemp(
  resolve(tmpdir(), "openepm-definition-lifecycle-"),
);
const app = {
  workspaceId: "fixture",
  applicationId: "lifecycle",
  name: "Lifecycle fixture",
  status: "Active",
};
const catalog = {
  applicationAccess: {
    issuer: "fixture",
    subjectId: "operator",
    role: "Editor",
    workspaceAdministrator: false,
  },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    [
      "application.rule.list",
      "application.rule.read",
      "application.rule.run",
      "calculated.member.list",
      "calculated.member.read",
      "python.program.read",
      "python.program.activate",
      "python.program.deactivate",
    ].map((name) => [name, {}]),
  ),
  revisions: {
    metadata: 4,
    policy: 2,
    security: 1,
    schemaEpoch: 1,
    data: 0,
    commit: 0,
  },
};
const entry = `import React,{useState} from 'react';import {createRoot} from 'react-dom/client';import {BuildRules} from '/src/BuildRules.tsx';import {CalculatedMembers} from '/src/CalculatedMembers.tsx';import '/src/styles.css';
function Fixture(){const[state,setState]=useState({surface:'rule',revision:1,revoked:false});window.updateLifecycleFixture=setState;
const catalog=${JSON.stringify(catalog)};catalog.revisions.security=state.revision;if(state.revoked)delete catalog.functions['application.rule.run'];
return React.createElement('main',null,state.surface==='rule'?React.createElement(BuildRules,{app:${JSON.stringify(app)},catalog}):React.createElement(CalculatedMembers,{app:${JSON.stringify(app)},catalog}));}
createRoot(document.getElementById('root')).render(React.createElement(Fixture));`;
const server = await createServer({
  root: webRoot,
  cacheDir,
  server: { host: "127.0.0.1", port: 0 },
  logLevel: "error",
  clearScreen: false,
  plugins: [
    {
      name: "isolated-definition-lifecycle",
      enforce: "pre",
      resolveId(id) {
        if (id === "virtual:definition-lifecycle")
          return "\0definition-lifecycle";
        if (/(?:^|\/)PythonRuleEditor(?:\.tsx)?$/.test(id))
          return "\0code-display";
      },
      load(id) {
        if (id === "\0definition-lifecycle") return entry;
        if (id === "\0code-display")
          return `import React from 'react';export function PythonRuleEditor({value,ariaLabel}){return React.createElement('pre',{'aria-label':ariaLabel||'Fixture source text'},value);}`;
      },
    },
  ],
});
const report = {
  method:
    "Real Chromium BuildRules, CalculatedMembers and PythonDefinitionEditor; mocked API and code-display widget; no database, OIDC or sandbox qualification",
  cases: [],
  pageErrors: [],
  unexpectedApi: [],
  source: [],
};
for (const path of [
  "definition-lifecycle.ts",
  "BuildRules.tsx",
  "CalculatedMembers.tsx",
  "PythonDefinitionEditor.tsx",
  "CapabilityArea.tsx",
])
  report.source.push({
    path: "web-ui/src/" + path,
    sha256: createHash("sha256")
      .update(await readFile(resolve(webRoot, "src", path)))
      .digest("hex"),
  });
async function textIs(locator, expected) {
  await locator.waitFor({ state: "visible" });
  assert.equal((await locator.textContent()).trim(), expected);
}
async function disabledIs(locator, expected) {
  await locator.waitFor({ state: "visible" });
  assert.equal(await locator.isDisabled(), expected);
}
let browser;
try {
  await server.listen();
  const origin = server.resolvedUrls.local[0].replace(/\/$/, "");
  browser = await playwright.chromium.launch({ headless: true });
  report.browser = browser.version();
  for (const width of [650, 1280]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } });
    page.on("pageerror", (error) => report.pageErrors.push(error.message));
    let mode = "active",
      surface = "rule",
      revision = 1;
    const state = () => ({
      defined: true,
      status: mode === "inactive" ? "Inactive" : "Active",
      active: mode !== "inactive",
      sourceCurrent: true,
      valid: mode === "active",
      executable: mode === "active",
      reason:
        mode === "active"
          ? null
          : mode === "inactive"
            ? "validation_required"
            : mode === "dependency"
              ? "dependency_stale"
              : "source_environment_stale",
    });
    const source = () => ({
      ...state(),
      programId: "source",
      stateToken: "b".repeat(64),
      sourceToken: "c".repeat(64),
      sourceDigest: "d".repeat(64),
      sourceText: "def build(context, parameters):\n    return definition",
      entryPoint: "build",
      environmentId: "approved",
      environmentStateToken: "e".repeat(64),
      parameterSchema: { type: "object" },
      validation: {
        buildId: "0".repeat(32),
        purpose: "Validation",
        status: "expired",
        current: false,
      },
    });
    const binding = () => ({
      programId: "source",
      programSourceToken: "c".repeat(64),
      sourceDigest: "d".repeat(64),
      buildId: mode === "inactive" ? null : "0".repeat(32),
      active: state().active,
    });
    const summary = () => ({
      ...state(),
      [surface === "rule" ? "ruleId" : "definitionId"]: "forecast",
      stateToken: "b".repeat(64),
      programDigest: mode === "inactive" ? null : "a".repeat(64),
      metadataCurrent: true,
      definitionMetadataRevision: 4,
      ...(surface === "calculation" && mode !== "inactive"
        ? {
            evaluation: "materialized",
            dependencies: [],
            target: { dimensionId: "Account", memberId: "Forecast" },
            resultUnit: "amount",
          }
        : {}),
    });
    const detail = () => ({
      ...summary(),
      source: binding(),
      currentMetadataRevision: 4,
      policyRevision: 2,
      updatedAt: "2026-11-17T12:00:00Z",
      program:
        mode === "inactive"
          ? null
          : surface === "rule"
            ? { function: "application.rule.plan", arguments: {} }
            : {
                function: "calculated.member.definition",
                arguments: {
                  format: "openepm-calculated-member-v1",
                  definitionId: "forecast",
                  name: "Forecast",
                  target: { dimensionId: "Account", memberId: "Forecast" },
                  evaluation: "materialized",
                  sourceSelection: { dimensions: [] },
                  expression: { op: "AmountLiteral", decimal: "1" },
                  dependencies: [],
                  resultUnit: "amount",
                  resultKey: "forecast.result",
                  maxSourceCells: 100,
                  maxOutputCells: 100,
                },
              },
    });
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith("/definition-lifecycle.html"))
        return route.fulfill({
          contentType: "text/html",
          body: await server.transformIndexHtml(
            "/definition-lifecycle.html",
            '<html><body><div id="root"></div><script type="module" src="/@id/virtual:definition-lifecycle"></script></body></html>',
          ),
        });
      if (!url.pathname.startsWith("/api/")) return route.continue();
      const body = route.request().postDataJSON(),
        fn = body.program?.function;
      let result;
      if (fn === "application.rule.list")
        result = {
          rows: [summary()],
          hasMore: false,
          nextAfterRuleId: null,
          metadataRevision: 4,
          policyRevision: 2,
        };
      else if (fn === "calculated.member.list")
        result = {
          rows: [summary()],
          hasMore: false,
          nextAfterDefinitionId: null,
          metadataRevision: 4,
          policyRevision: 2,
        };
      else if (
        fn === "application.rule.read" ||
        fn === "calculated.member.read"
      )
        result = detail();
      else if (fn === "python.program.read") result = source();
      else {
        report.unexpectedApi.push(fn || url.pathname);
        return route.fulfill({
          status: 400,
          contentType: "application/json",
          body: JSON.stringify({ code: "UNEXPECTED_FIXTURE_EFFECT" }),
        });
      }
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ result }),
      });
    });
    await page.goto(origin + "/definition-lifecycle.html");
    await page.waitForFunction(
      () => typeof window.updateLifecycleFixture === "function",
    );
    for (surface of ["rule", "calculation"]) {
      for (mode of ["active", "dependency", "environment", "inactive"]) {
        await page.evaluate((state) => window.updateLifecycleFixture(state), {
          surface,
          revision: ++revision,
          revoked: false,
        });
        const open = page.getByRole("button", {
          name: surface === "rule" ? "forecast" : "Open current forecast",
          exact: true,
        });
        await open.click();
        const availability = page.getByLabel(
          "Current definition availability",
          { exact: true },
        );
        const expected =
          mode === "active"
            ? "Executable"
            : mode === "inactive"
              ? "Current definition validation required"
              : mode === "dependency"
                ? "Revalidation required · definition dependencies changed"
                : "Revalidation required · source environment changed";
        await textIs(availability, expected);
        await page
          .getByText(/Validation: expired/)
          .waitFor({ state: "visible" });
        await page
          .getByText(/An expired build does not itself deactivate/)
          .waitFor({ state: "visible" });
        await disabledIs(
          page.getByRole("button", { name: "Activate source", exact: true }),
          true,
        );
        if (surface === "rule") {
          const run = page.getByRole("button", {
            name: "Run rule",
            exact: true,
          });
          await disabledIs(run, mode !== "active");
        }
        if (mode === "inactive")
          await page
            .getByText(
              surface === "rule"
                ? /No current compiled rule is available/
                : /Current compiled details are unavailable/,
            )
            .waitFor({ state: "visible" });
        report.cases.push({
          width,
          surface,
          mode,
          technicalValidation: "expired",
          ownerAvailability: expected,
          actionsChecked: true,
        });
      }
    }
    surface = "rule";
    mode = "active";
    await page.evaluate((state) => window.updateLifecycleFixture(state), {
      surface,
      revision: ++revision,
      revoked: true,
    });
    await page.getByRole("button", { name: "forecast", exact: true }).click();
    await textIs(
      page.getByLabel("Current definition availability", { exact: true }),
      "Executable",
    );
    assert.equal(
      await page.getByRole("button", { name: "Run rule", exact: true }).count(),
      0,
    );
    report.cases.push({
      width,
      surface,
      mode: "actor-run-revoked",
      ownerAcceptancePreserved: true,
      freshRunHidden: true,
    });
    await page.close();
  }
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(report.unexpectedApi, []);
  report.passed = true;
} finally {
  if (browser) await browser.close();
  await server.close();
  await rm(cacheDir, { recursive: true, force: true });
  report.cleanup = {
    browserClosed: true,
    serverClosed: true,
    ownedCacheRemoved: true,
  };
  if (process.argv[2])
    await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n");
}
process.stdout.write(
  JSON.stringify({
    passed: report.passed,
    cases: report.cases.length,
    pageErrors: report.pageErrors,
    unexpectedApi: report.unexpectedApi,
    cleanup: report.cleanup,
  }) + "\n",
);
