import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
const widths = JSON.parse(
  process.env.OPEN_EPM_GRID_WIDTHS || "[1280,650,651,684,950,951,320]",
);
const canonicalLayoutOnly = process.argv.includes("--canonical-layout");
const viewportHeight = Number(process.env.OPEN_EPM_GRID_HEIGHT || 1000);
const root = process.cwd(),
  web = resolve(root, "web-ui");
const require = createRequire(resolve(web, "package.json"));
const { chromium } = require(
  resolve(
    execFileSync("npm", ["root", "--global"], { encoding: "utf8" }).trim(),
    "playwright",
  ),
);
const { createServer } = await import(
  resolve(web, "node_modules/vite/dist/node/index.js")
);
const scratch = await mkdtemp(resolve(tmpdir(), "openepm-ip13-grid-"));
const server = await createServer({
  root: web,
  cacheDir: scratch,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
});
const files = [
  "web-ui/src/Analyze.tsx",
  "web-ui/src/grid-focus.ts",
  "web-ui/src/exact-cell-mutation.tsx",
  "web-ui/src/App.tsx",
  "web-ui/src/unsaved-work.ts",
  "web-ui/src/grid-read-contract.ts",
  "web-ui/src/styles.css",
  "web-ui/src/data-workspaces.css",
];
const manifest = async () =>
  Promise.all(
    files.map(async (path) => ({
      path,
      sha256: createHash("sha256")
        .update(await readFile(resolve(root, path)))
        .digest("hex"),
    })),
  );
const before = await manifest();
const report = {
  method:
    "Read-only source assessment with real Chromium App/Analyze and intercepted synthetic APIs only. Mock conflict and lost-response paths cause no server effect.",
  sourceFiles: before,
  sourceChanged: false,
  pageErrors: [],
  unknownApi: [],
  observations: [],
  qualificationGaps: [
    "320 CSS-pixel viewport is the reflow equivalent of a 1280px layout at 400%; native browser zoom and assistive technology are not exercised.",
    "Synthetic two-axis grid is a keyboard/layout fixture, not domain/security/whole-grain qualification.",
  ],
};
const json = (body, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});
let browser;
const describe = (page) =>
  page.evaluate(() => {
    const x = document.activeElement;
    return {
      tag: x?.tagName,
      role: x?.getAttribute("role"),
      label:
        x?.getAttribute("aria-label") || x?.textContent?.trim().slice(0, 180),
      row: x?.getAttribute("data-grid-row"),
      column: x?.getAttribute("data-grid-column"),
      tabIndex: x?.tabIndex,
      disabled: x?.disabled ?? false,
    };
  });
try {
  await server.listen();
  const base = "http://127.0.0.1:" + server.httpServer.address().port;
  browser = await chromium.launch({ headless: true });
  report.browserVersion = browser.version();
  async function setup(
    width,
    longLabels = false,
    mutation = "none",
    flat = false,
    presentationProbe = null,
  ) {
    const context = await browser.newContext({
        viewport: { width, height: viewportHeight },
      }),
      page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.on("pageerror", (e) => report.pageErrors.push(e.message));
    page.on("dialog", (d) => d.accept());
    const rowIds = presentationProbe
      ? Array.from(
          { length: Math.max(1, presentationProbe.values.length) },
          (_, i) => `Metric-${i}`,
        )
      : longLabels
        ? [
            "Department_" + "LongBusinessLabel_".repeat(7) + "Cost",
            "Department_" + "LongBusinessLabel_".repeat(7) + "Hours",
            "Department_" + "LongBusinessLabel_".repeat(7) + "Rate",
          ]
        : ["Cost", "Hours", "Rate"];
    const columnIds = presentationProbe
      ? ["Jan"]
      : longLabels
        ? Array.from(
            { length: 4 },
            (_, i) =>
              "FinancialYear2026_" + "LongReportingPeriod_".repeat(5) + (i + 1),
          )
        : ["Jan", "Feb", "Mar", "Apr"];
    const dimensionIds = presentationProbe?.definition
      ? presentationProbe.definition.selection.dimensions.map(
          (axis) => axis.dimensionId,
        )
      : longLabels
        ? [
            "Account_" + "LongDimensionName_".repeat(7),
            "Period_" + "LongDimensionName_".repeat(7),
          ]
        : ["Account", "Period"];
    const application = {
      workspaceId: "fixture",
      applicationId: "grid",
      name: "Dense grid fixture",
      status: "Active",
      kind: "blank",
    };
    const catalog = {
      applicationAccess: {
        role: "Editor",
        workspaceAdministrator: false,
        issuer: "fixture",
        subjectId: "operator",
      },
      enabledCapabilities: [],
      functions: Object.fromEntries(
        [
          "metadata.dimension.list",
          "metadata.member.list",
          "facts.cube.scan",
          "facts.numeric.batch",
          "facts.cell.editability.read",
        ].map((k) => [k, {}]),
      ),
      revisions: { metadata: 2, data: 2, policy: 1, security: 1, commit: 2 },
    };
    const definition =
      presentationProbe &&
      (presentationProbe.definition || {
        format: "openepm-cube-view-v1",
        viewId: "presentation",
        name: "Presentation fixture",
        selection: {
          format: "openepm-cube-selection-v1",
          metadataRevision: 2,
          dimensions: dimensionIds.map((dimensionId, i) => ({
            dimensionId,
            include: { kind: "members", memberIds: i ? columnIds : rowIds },
            exclude: null,
          })),
        },
        layout: {
          pages: [],
          rows: [dimensionIds[0]],
          columns: [dimensionIds[1]],
          filters: [],
        },
        dataSource: { kind: "raw", resultKey: null },
        suppression: { missing: false, zero: false },
        pageSize: presentationProbe.pageSize || 100,
      });
    if (presentationProbe) {
      catalog.functions["grid.definition.list"] = {};
      catalog.functions["facts.cube.resolved.read"] = {
        canonicalViewRead: "openepm-cube-view-read-v1",
      };
    }
    let releasePendingRead = null;
    let gridReads = 0,
      effectCalls = 0,
      admissions = 0,
      firstPacket = null;
    const cells = (next = false) =>
      rowIds.flatMap((r, i) =>
        columnIds.map((c, j) => ({
          members: {
            [dimensionIds[0]]: next ? r + "Next" : r,
            [dimensionIds[1]]: c,
          },
          kind: "numeric",
          amount: `${100 + i * 10 + j}.00000000`,
          numericChangeId: "fixture-cell-" + i + "-" + j,
          lastRevision: 2,
        })),
      );
    await page.route("**/*", async (route) => {
      const u = new URL(route.request().url());
      if (u.origin !== base) return route.abort();
      if (!u.pathname.startsWith("/api/")) return route.continue();
      const body = route.request().postDataJSON(),
        path = u.pathname;
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
      if (path === "/api/preview")
        return route.fulfill(
          json({
            previewToken: "fixture-exact-preview-token",
            programDigest: "b".repeat(64),
            revisionVector: { data_revision: 2 },
          }),
        );
      if (path === "/api/operation-admission") {
        admissions++;
        return route.fulfill(
          json({
            operationId: `oa1_zz_${"a".repeat(32)}_${"A".repeat(43)}`,
            expiresAt: Math.floor(Date.now() / 1000) + 900,
            intentDigest: "c".repeat(64),
          }),
        );
      }
      if (path === "/api/submit") {
        effectCalls++;
        if (!firstPacket) firstPacket = body;
        else
          assert.deepEqual(
            body,
            firstPacket,
            "Reconcile must replay exact original packet",
          );
        if (effectCalls > 1)
          return route.fulfill(
            json({ jobId: "d".repeat(32), status: "ready" }),
          );
        if (mutation === "conflict")
          return route.fulfill(
            json({ code: "STALE_OR_MISMATCHED_V2_PREVIEW" }, 400),
          );
        if (mutation === "unknown") return route.abort("failed");
        throw new Error("Unexpected fixture effect");
      }
      if (path === "/api/job" && mutation === "unknown") {
        assert.deepEqual(body, {
          workspaceId: application.workspaceId,
          applicationId: application.applicationId,
          operationId: firstPacket.idempotencyKey,
        });
        return route.fulfill(json({ job_id: "d".repeat(32), status: "ready" }));
      }
      if (path === "/api/read") {
        const fn = body.program.function,
          args = body.program.arguments;
        if (presentationProbe && fn === "grid.definition.list")
          return route.fulfill(
            json({
              result: {
                grids: [
                  {
                    gridId: definition.viewId,
                    name: definition.name,
                    definition,
                    stateToken: "c".repeat(64),
                    metadataRevision: 2,
                    canonicalDigest: "fixture-view-digest",
                    creator: { issuer: "fixture", subjectId: "operator" },
                  },
                ],
                nextAfterGridId: null,
                collectionToken: "d".repeat(64),
              },
            }),
          );
        if (presentationProbe && fn === "facts.cube.resolved.read") {
          gridReads++;
          assert.deepEqual(
            args.view,
            presentationProbe.expectedView || definition,
          );
          const readPolicy = {
            semantics: definition.dataSource.kind === "raw" ? "own" : "stored",
          };
          assert.deepEqual(args.readPolicy, readPolicy);
          const outcome = await new Promise((resolve) => {
            releasePendingRead = resolve;
          });
          releasePendingRead = null;
          if (outcome === "failure")
            return route.fulfill(
              json({ code: "CUBE_VIEW_READ_BUDGET_EXCEEDED" }, 400),
            );
          const values =
            outcome === "text"
              ? [
                  [
                    {
                      present: true,
                      value: "",
                      unit: "text",
                      origin: "input",
                      currentness: "current",
                      resultStateToken: null,
                    },
                  ],
                ]
              : presentationProbe.values;
          return route.fulfill(
            json({
              result: {
                format: "openepm-cube-view-read-v1",
                dataSource: definition.dataSource,
                readPolicy,
                complete: true,
                snapshot: { commitRevision: 2 },
                presentation: {
                  pageSize: definition.pageSize,
                  rowCount: values.length,
                },
                rows: values.map((raw, i) => ({
                  members: presentationProbe.definition
                    ? Object.fromEntries(
                        definition.selection.dimensions.map((axis) => [
                          axis.dimensionId,
                          axis.include.kind === "member"
                            ? axis.include.memberId
                            : axis.include.memberIds[0],
                        ]),
                      )
                    : { Account: rowIds[i], Period: "Jan" },
                  values:
                    definition.dataSource.kind === "calculated"
                      ? { calculated: raw }
                      : definition.dataSource.kind === "combined"
                        ? { raw, calculated: raw }
                        : { raw },
                })),
              },
            }),
          );
        }
        if (fn === "metadata.dimension.list")
          return route.fulfill(
            json({
              result: {
                rows: dimensionIds.map((id, index) => ({
                  dimension_id: id,
                  name: id,
                  model_role: index === 0 ? "Account" : "Period",
                  status: "Active",
                })),
                nextAfterDimensionId: null,
                metadataRevision: 2,
              },
            }),
          );
        if (fn === "metadata.member.list")
          return route.fulfill(
            json({
              result: {
                rows: (presentationProbe?.definition
                  ? (() => {
                      const axis = definition.selection.dimensions.find(
                        (item) =>
                          item.dimensionId ===
                          (args.dimensionId || args.dimension),
                      );
                      return axis.include.kind === "member"
                        ? [axis.include.memberId]
                        : axis.include.memberIds;
                    })()
                  : (args.dimensionId || args.dimension) === dimensionIds[0]
                    ? rowIds
                    : columnIds
                ).map((id) => ({ member_id: id, name: id, status: "Active" })),
                nextAfterMemberId: null,
                metadataRevision: 2,
              },
            }),
          );
        if (fn === "facts.cell.editability.read") {
          if (presentationProbe?.denyInspection)
            return route.fulfill(
              json({ code: "APPLICATION_GRANT_REQUIRED" }, 403),
            );
          return route.fulfill(
            json({
              result: {
                editable: args.source !== "calculated",
                reasonCode:
                  args.source === "calculated"
                    ? "CALCULATED_RESULT_READ_ONLY"
                    : "RAW_INPUT_EDITABLE",
                message:
                  args.source === "calculated"
                    ? "Calculated results are read only."
                    : "Current raw input is editable.",
              },
            }),
          );
        }
        if (fn === "facts.cube.scan") {
          if (args.includeMissing)
            return route.fulfill(
              json({
                result: {
                  rows: cells().filter((c) =>
                    Object.entries(args.members).every(
                      ([k, v]) => c.members[k] === v,
                    ),
                  ),
                  snapshotRevision: 2,
                  nextCursor: null,
                  source: "raw",
                },
              }),
            );
          gridReads++;
          return route.fulfill(
            json({
              result: {
                rows: flat
                  ? [
                      ...cells(Boolean(args.cursor)),
                      {
                        ...cells(Boolean(args.cursor))[0],
                        kind: "text",
                        text: "A note",
                      },
                    ]
                  : cells(Boolean(args.cursor)),
                snapshotRevision: 2,
                nextCursor: args.cursor ? null : "fixture-page-2",
                source: "raw",
              },
            }),
          );
        }
      }
      report.unknownApi.push({ path, fn: body?.program?.function });
      return route.fulfill(json({ code: "UNEXPECTED_FIXTURE_API" }, 400));
    });
    await page.goto(base + "/#/grid/0?workspace=fixture&application=grid");
    if (presentationProbe) {
      await page
        .getByRole("button", { name: "Open view", exact: true })
        .click();
      return {
        context,
        page,
        counts: () => ({ gridReads, effectCalls, admissions }),
        releaseRead: (outcome = "success") => {
          assert.ok(releasePendingRead, "Expected one pending canonical read");
          releasePendingRead(outcome);
        },
        readPending: () => Boolean(releasePendingRead),
      };
    }
    await page
      .getByRole("button", { name: "Configure layout", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Suggest layout", exact: true })
      .click();
    await page.getByRole("button", { name: "Read grid", exact: true }).click();
    await page.locator('[data-grid-row="0"][data-grid-column="0"]').waitFor();
    return {
      context,
      page,
      counts: () => ({ gridReads, effectCalls, admissions }),
    };
  }
  for (const width of canonicalLayoutOnly ? [] : widths)
    for (const longLabels of [false, true])
      for (const flat of [false, true]) {
        const { context, page, counts } = await setup(
          width,
          longLabels,
          "none",
          flat,
        );
        const item = {
          widthCssPixels: width,
          heightCssPixels: viewportHeight,
          longLabels,
          flat,
          cases: {},
        };
        report.inProgressCase = item;
        const first = page.locator('[data-grid-row="0"][data-grid-column="0"]');
        await first.focus();
        await page.keyboard.press("ArrowDown");
        await page.keyboard.press("ArrowRight");
        await page.keyboard.press("ArrowRight");
        item.cases.afterArrows = await describe(page);
        assert.equal(item.cases.afterArrows.row, "1");
        assert.equal(item.cases.afterArrows.column, flat ? "0" : "2");
        assert.equal(item.cases.afterArrows.tabIndex, 0);
        item.cases.tabStops = await page
          .locator('.cell-button[tabindex="0"]')
          .evaluateAll((xs) =>
            xs.map((x) => ({
              row: x.dataset.gridRow,
              column: x.dataset.gridColumn,
            })),
          );
        item.cases.layout = await page.evaluate(() => {
          const b = document.activeElement,
            r = b.getBoundingClientRect(),
            s = b.closest(".react-grid-scroll"),
            g = s.getBoundingClientRect();
          const left = Math.max(r.left, g.left, 0),
            right = Math.min(r.right, g.right, innerWidth),
            top = Math.max(r.top, g.top, 0),
            bottom = Math.min(r.bottom, g.bottom, innerHeight);
          const hit =
            right > left && bottom > top
              ? document.elementFromPoint(
                  (left + right) / 2,
                  (top + bottom) / 2,
                )
              : null;
          return {
            viewport: innerWidth,
            pageScrollWidth: document.documentElement.scrollWidth,
            gridClientWidth: s.clientWidth,
            gridScrollWidth: s.scrollWidth,
            gridScrollLeft: s.scrollLeft,
            stickyHeaderWidth: b
              .closest("tr")
              .querySelector("th")
              .getBoundingClientRect().width,
            focusedCellRect: {
              left: r.left,
              right: r.right,
              top: r.top,
              bottom: r.bottom,
            },
            focusedCellHitVisible: Boolean(
              hit && (hit === b || b.contains(hit)),
            ),
            coveringElement: hit?.tagName,
            coveringText: hit?.textContent?.slice(0, 80),
          };
        });
        assert.equal(
          item.cases.layout.pageScrollWidth,
          width,
          "Page must not overflow",
        );
        assert.equal(
          item.cases.layout.focusedCellHitVisible,
          true,
          "Focused value must remain visible beside sticky labels",
        );
        assert.equal(item.cases.tabStops.length, 1);
        await page.keyboard.press("Tab");
        item.cases.afterTab = await describe(page);
        await page.keyboard.press("Shift+Tab");
        item.cases.afterReturnTab = await describe(page);
        assert.equal(
          item.cases.afterReturnTab.label,
          item.cases.afterArrows.label,
          "Grid re-entry retains coordinate",
        );
        if (!longLabels) {
          await page
            .getByRole("button", { name: "Read grid", exact: true })
            .focus();
          await page.keyboard.press("Enter");
          await page
            .getByRole("button", { name: "Read grid", exact: true })
            .waitFor();
          await page.waitForFunction(
            () =>
              !Array.from(document.querySelectorAll("button")).find(
                (b) => b.textContent === "Read grid",
              )?.disabled,
          );
          item.cases.afterRefresh = await describe(page);
          assert.equal(item.cases.afterRefresh.label, "Read grid");
          await page
            .getByRole("button", { name: "Next page", exact: true })
            .focus();
          await page.keyboard.press("Enter");
          await page
            .locator(".cell-button")
            .first()
            .getAttribute("aria-label")
            .then(async () => {
              await page.waitForFunction(() =>
                document
                  .querySelector(".cell-button")
                  ?.getAttribute("aria-label")
                  ?.includes("Next"),
              );
            });
          item.cases.afterPage = await describe(page);
          assert.equal(item.cases.afterPage.row, "1");
          assert.equal(item.cases.afterPage.column, flat ? "0" : "2");
          assert.ok(item.cases.afterPage.label.includes("Next"));
        }
        item.counts = counts();
        report.observations.push(item);
        delete report.inProgressCase;
        await context.close();
      }
  for (const width of canonicalLayoutOnly ? [] : widths)
    for (const mutation of ["conflict", "unknown"]) {
      const { context, page, counts } = await setup(width, false, mutation);
      const item = {
        widthCssPixels: width,
        heightCssPixels: viewportHeight,
        mutation,
        cases: {},
      };
      await page.locator('[data-grid-row="1"][data-grid-column="1"]').focus();
      await page.keyboard.press("Enter");
      await page
        .getByRole("heading", {
          name: "Details and exact writeback",
          exact: true,
        })
        .waitFor();
      item.cases.openInspector = await describe(page);
      await page.getByLabel("Value", { exact: true }).fill("5.00000001");
      await page
        .getByRole("button", { name: "Preview exact mutation", exact: true })
        .click();
      await page.getByLabel("I reviewed this exact cell mutation").check();
      await page
        .getByRole("button", { name: "Submit durable writeback", exact: true })
        .focus();
      await page.keyboard.press("Enter");
      if (mutation === "conflict")
        await page
          .getByText(/Reread the current values and preview the edit again/)
          .waitFor();
      else await page.getByText(/Mutation outcome unknown/).waitFor();
      item.cases.afterOutcome = await describe(page);
      if (mutation === "conflict") {
        assert.equal(item.cases.afterOutcome.role, "alert");
        assert.match(
          item.cases.afterOutcome.label,
          /This edit needs a fresh preview/,
        );
        await page.keyboard.press("Tab");
        item.cases.nextFocus = await describe(page);
        assert.equal(
          item.cases.nextFocus.label,
          "Reread current cell and keep my edit",
        );
        assert.equal(
          await page.getByLabel("Value", { exact: true }).inputValue(),
          "5.00000001",
        );
      } else {
        assert.equal(item.cases.afterOutcome.label, "Retry connection");
        await page.keyboard.press("Enter");
        await page
          .getByRole("button", {
            name: "Check original mutation status",
            exact: true,
          })
          .waitFor();
        item.cases.afterReconnect = await describe(page);
        assert.equal(
          await page
            .locator("[data-grid-focus-outcome]")
            .evaluate((el) => el === document.activeElement),
          true,
          "Restored current-owner recovery receives focus",
        );
        await page.keyboard.press("Tab");
        assert.equal(
          (await describe(page)).label,
          "Check original mutation status",
        );
        await page.keyboard.press("Enter");
        await page.getByText(/Request status: ready/).waitFor();
        item.cases.afterReconcile = await describe(page);
        assert.equal(
          await page
            .locator("[data-grid-focus-outcome]")
            .evaluate((el) => el === document.activeElement),
          true,
          "Confirmed reconciliation receives outcome focus",
        );
        await page.keyboard.press("Tab");
        assert.equal((await describe(page)).label, "Refresh mutation status");
        assert.equal(counts().admissions, 1);
        assert.equal(counts().effectCalls, 1);
      }
      item.counts = counts();
      report.observations.push(item);
      delete report.inProgressCase;
      await context.close();
    }
  const value = (amount, unit = "amount") => ({
    present: amount !== null,
    value: amount,
    unit,
    origin: "input",
    currentness: "current",
    resultStateToken: null,
  });
  const presentationCases = [
    { name: "empty", values: [], reason: "loaded page has none" },
    {
      name: "missing",
      values: [[value(null)]],
      reason: "missing values are not treated as zero",
    },
    {
      name: "empty-text",
      values: [[value("", "text")]],
      reason: "loaded page contains text",
    },
    {
      name: "mixed",
      values: [[value("0.00000000")], [value("note", "text")]],
      reason: "loaded page contains text",
    },
    {
      name: "currency-conflict",
      values: [
        [value("1.20000000", { type: "currency", memberId: "CHF" })],
        [value("1.30000000", { type: "currency", memberId: "USD" })],
      ],
      reason: "loaded page contains different units",
    },
    {
      name: "separate-values",
      values: [[value("1.00000000"), value("2.00000000")]],
      reason: "require one value per coordinate",
    },
    {
      name: "zero-and-missing",
      values: [[value("0.00000000")], [value(null, "ratio")]],
      label: "0.00000000",
      cards: 1,
      scope: "Missing values are omitted, not converted to zero.",
    },
    {
      name: "currency",
      values: [
        [value("1.20000000", { type: "currency", memberId: "CHF" })],
        [value("1.30000000", { memberId: "CHF", type: "currency" })],
      ],
      label: "1.20000000 CHF",
      cards: 2,
      scope: "Showing 2 of 2 present numeric values",
    },
    {
      name: "card-bound",
      values: Array.from({ length: 25 }, () => [value("0.00000000")]),
      label: "0.00000000",
      cards: 24,
      scope: "Showing 24 of 25 present numeric values",
    },
    {
      name: "paged",
      values: [[value("1.00000000")], [value("2.00000000")]],
      pageSize: 1,
      label: "1.00000000",
      cards: 1,
      scope:
        "More grid pages are available; this is not the complete selection.",
    },
  ];
  for (const width of canonicalLayoutOnly ? [] : [1280, 320])
    for (const scenario of presentationCases) {
      const { context, page, counts, releaseRead, readPending } = await setup(
        width,
        false,
        "none",
        false,
        scenario,
      );
      const note = page.locator(".grid-panel > .context-note");
      const item = {
        kind: "numeric-presentation",
        widthCssPixels: width,
        scenario: scenario.name,
        observations: {},
      };
      report.inProgressCase = item;
      assert.equal(
        await page.getByText("No snapshot read", { exact: true }).count(),
        1,
      );
      assert.match(await note.innerText(), /Read the grid/);
      assert.equal(counts().gridReads, 0);
      async function beginRead() {
        await page
          .getByRole("button", { name: "Read grid", exact: true })
          .click();
        for (let attempt = 0; !readPending() && attempt < 300; attempt++)
          await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(readPending(), true, "Expected current pending read");
      }
      await beginRead();
      assert.equal(
        await page.getByLabel("Loaded grid read", { exact: true }).count(),
        0,
      );
      assert.match(await note.innerText(), /Reading the grid/);
      releaseRead();
      await page.getByLabel("Loaded grid read", { exact: true }).waitFor();
      if (scenario.reason) {
        assert.equal(
          await page
            .getByRole("button", { name: "KPI", exact: true })
            .isDisabled(),
          true,
        );
        assert.equal(
          await page
            .getByRole("button", { name: "Chart", exact: true })
            .isDisabled(),
          true,
        );
        assert.ok((await note.innerText()).includes(scenario.reason));
        for (const name of ["KPI", "Chart"]) {
          const described = await page
            .getByRole("button", { name, exact: true })
            .evaluate(
              (el) =>
                document.getElementById(el.getAttribute("aria-describedby"))
                  ?.textContent,
            );
          assert.ok(described.includes(scenario.reason));
        }
        if (scenario.name === "empty") {
          assert.ok(
            (
              await page.getByLabel("Current empty result").innerText()
            ).includes("requested view was read successfully"),
          );
          assert.ok(
            !(
              await page.getByLabel("Current empty result").innerText()
            ).includes("calculation completed"),
          );
        }
        item.observations.disabledReason = await note.innerText();
      } else {
        await page.getByRole("button", { name: "KPI", exact: true }).click();
        const cards = page.getByLabel("Snapshot KPI cards");
        await cards.waitFor();
        assert.equal(await cards.locator("article").count(), scenario.cards);
        assert.equal(
          await cards.locator("strong").first().innerText(),
          scenario.label,
        );
        assert.ok((await note.innerText()).includes(scenario.scope));
        item.observations.numericScope = await note.innerText();
        await page.getByRole("button", { name: "Chart", exact: true }).click();
        assert.equal(
          await page
            .getByLabel("Snapshot value chart")
            .locator("strong")
            .first()
            .innerText(),
          scenario.label,
        );
        if (scenario.name === "paged") {
          await page
            .getByRole("button", { name: "Next page", exact: true })
            .click();
          await page
            .getByLabel("Snapshot value chart")
            .getByText("2.00000000", { exact: true })
            .waitFor();
          assert.equal(
            await page
              .getByRole("button", { name: "Next page", exact: true })
              .isDisabled(),
            true,
          );
          assert.ok(!(await note.innerText()).includes("More grid pages"));
          assert.equal(
            counts().gridReads,
            1,
            "Canonical pagination reuses its completed read",
          );
        }
        await beginRead();
        releaseRead("text");
        await page.getByText(/loaded page contains text/).waitFor();
        assert.equal(
          await page
            .getByRole("group", { name: "Analyze presentation" })
            .getByRole("button", { name: "Grid", exact: true })
            .getAttribute("aria-pressed"),
          "true",
        );
        assert.equal(await page.getByLabel("Snapshot value chart").count(), 0);
        item.observations.incompatibleRefreshReturnsToGrid = true;
      }
      await beginRead();
      releaseRead("failure");
      await page
        .getByRole("alert")
        .filter({ hasText: "CUBE_VIEW_READ_BUDGET_EXCEEDED" })
        .waitFor();
      assert.equal(
        await page.getByLabel("Loaded grid read", { exact: true }).count(),
        0,
      );
      assert.equal(
        await page.getByText("No snapshot read", { exact: true }).count(),
        1,
      );
      assert.equal(
        await page
          .getByRole("button", { name: "Chart", exact: true })
          .isDisabled(),
        true,
      );
      assert.equal(await page.getByLabel("Snapshot value chart").count(), 0);
      assert.equal(await page.locator(".cell-button").count(), 0);
      assert.match(await note.innerText(), /Read the grid/);
      item.observations.failedReadClearsPresentation = true;
      assert.equal(counts().effectCalls, 0);
      assert.equal(counts().admissions, 0);
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth),
        width,
      );
      item.counts = counts();
      report.observations.push(item);
      delete report.inProgressCase;
      await context.close();
    }
  for (const width of widths)
    for (const kind of ["calculated", "combined"]) {
      const rowAxes = [
        "Company",
        "Region",
        "Product",
        "Channel",
        "Measure",
        "Currency",
      ];
      const columnAxes = ["Year", "Month"];
      const filters = [
        "Version",
        "CostCenter",
        "ServiceClass",
        "Location",
        "PlanStage",
        "FiscalBasis",
      ];
      const definition = {
        format: "openepm-cube-view-v1",
        viewId: "complete-view",
        name: "Complete canonical view",
        selection: {
          format: "openepm-cube-selection-v1",
          metadataRevision: 2,
          dimensions: [...rowAxes, ...columnAxes, "Scenario", ...filters].map(
            (dimensionId) => ({
              dimensionId,
              include: {
                kind: "members",
                memberIds: [`${dimensionId}-member`],
              },
              exclude:
                dimensionId === "Region"
                  ? { kind: "member", memberId: "Region-excluded" }
                  : null,
            }),
          ),
        },
        layout: {
          rows: rowAxes,
          columns: columnAxes,
          pages: ["Scenario"],
          filters,
        },
        dataSource: { kind, resultKey: "forecast.result" },
        suppression: { missing: true, zero: true },
        pageSize: 37,
      };
      const expectedView = {
        ...structuredClone(definition),
        layout: {
          rows: [
            "Region",
            "Company",
            "Product",
            "Channel",
            "Scenario",
            "Measure",
          ],
          columns: ["Month", "Year"],
          pages: [],
          filters: [...filters, "Currency"],
        },
      };
      const probe = {
        definition,
        expectedView,
        values: [[value("125.00000000")]],
      };
      const { context, page, counts, releaseRead, readPending } = await setup(
        width,
        false,
        "none",
        false,
        probe,
      );
      const item = {
        kind: "canonical-reshape",
        source: kind,
        widthCssPixels: width,
        observations: {},
      };
      report.inProgressCase = item;
      const layout = page.getByLabel("Current grid layout", { exact: true });
      const snapshotStatus = page.getByLabel("Grid snapshot status", {
        exact: true,
      });
      const loadedRead = page.getByLabel("Loaded grid read", { exact: true });
      assert.deepEqual(await layout.locator("strong").allTextContents(), [
        `6 axes · ${rowAxes.join(" / ")}`,
        `2 axes · ${columnAxes.join(" / ")}`,
        "1 axis · Scenario",
        `6 axes · ${filters.join(" / ")}`,
      ]);
      assert.match(await snapshotStatus.innerText(), /^Ready to configure/i);
      assert.equal(await loadedRead.count(), 0);
      assert.equal(counts().gridReads, 0);
      await page
        .getByRole("button", { name: "Configure layout", exact: true })
        .click();
      assert.match(
        await page
          .getByLabel("Pages, rows, columns and filters", { exact: true })
          .innerText(),
        /swapping its position/,
      );
      await page.getByLabel("Rows", { exact: true }).selectOption("Region");
      await page.getByLabel("Columns", { exact: true }).selectOption("Month");
      const currency = page.getByLabel("Currency axis location", {
        exact: true,
      });
      await currency.focus();
      await currency.selectOption("filters");
      assert.equal(
        await currency.evaluate((node) => document.activeElement === node),
        true,
      );
      await page
        .getByLabel("Scenario axis location", { exact: true })
        .selectOption("rows");
      await page
        .getByRole("button", {
          name: "Move Scenario earlier in Rows",
          exact: true,
        })
        .click();
      assert.deepEqual(await layout.locator("strong").allTextContents(), [
        `6 axes · ${expectedView.layout.rows.join(" / ")}`,
        "2 axes · Month / Year",
        "None",
        `7 axes · ${expectedView.layout.filters.join(" / ")}`,
      ]);
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth),
        width,
      );
      await page
        .getByRole("button", { name: "Close grid layout", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Read grid", exact: true })
        .click();
      for (let attempt = 0; !readPending() && attempt < 300; attempt++)
        await new Promise((resolve) => setTimeout(resolve, 10));
      assert.equal(readPending(), true);
      assert.match(await snapshotStatus.innerText(), /^Reading grid/i);
      assert.match(
        await page.locator(".grid-status").innerText(),
        /^Reading grid/i,
      );
      assert.equal(await loadedRead.count(), 0);
      assert.equal(await page.locator(".cell-button").count(), 0);
      const configure = page.getByRole("button", {
        name: "Configure layout",
        exact: true,
      });
      await configure.focus();
      releaseRead();
      const cell = page.locator(".cell-button").first();
      await cell.waitFor();
      assert.match(await snapshotStatus.innerText(), /^1 loaded cells/i);
      assert.equal(
        await loadedRead.innerText(),
        kind === "calculated"
          ? "Stored calculated result"
          : "Separate raw and calculated values",
      );
      assert.equal(
        await configure.evaluate((node) => document.activeElement === node),
        true,
      );
      await cell.click();
      await page
        .getByRole("button", { name: "Close writeback", exact: true })
        .click();
      assert.equal(
        await cell.evaluate((node) => document.activeElement === node),
        true,
      );
      assert.match(
        await page
          .getByLabel("Configured grid source", { exact: true })
          .innerText(),
        new RegExp(kind),
      );
      // A layout edit remains unpublished through cell navigation; the shell must
      // still disclose and guard it before sign-out, without creating any effect.
      await page.getByRole("button", { name: "Account", exact: true }).click();
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
      await page
        .getByRole("alertdialog", { name: "Discard unsaved changes?" })
        .waitFor();
      await page
        .getByRole("button", { name: "Keep editing", exact: true })
        .click();
      item.observations = {
        exactCanonicalRead: true,
        sourceSelectionExclusionSuppressionPageSizePreserved: true,
        crossRoleMoveAndReorder: true,
        moveRetainsFocus: true,
        inspectorReturnsFocusAndDraft: true,
        unsavedLayoutStillGuarded: true,
        documentReflow: true,
        configuredAxes: { rows: 6, columns: 2, fixed: 7 },
        pendingSnapshotEmpty: true,
        readCompletionRetainsFocus: true,
        snapshotRevision: 2,
      };
      probe.denyInspection = true;
      await cell.focus();
      await page.keyboard.press("Enter");
      await page
        .getByRole("alert")
        .filter({
          hasText: "Current access to this cell could not be confirmed.",
        })
        .waitFor();
      assert.equal(await page.locator(".cell-button").count(), 0);
      assert.equal(await loadedRead.count(), 0);
      assert.equal(
        await page.getByLabel("Cell details and writeback").count(),
        0,
      );
      assert.equal(
        await page.getByLabel("Calculated result provenance").count(),
        0,
      );
      assert.doesNotMatch(
        await page.locator("main").innerText(),
        /125\.00000000/,
      );
      assert.match(await snapshotStatus.innerText(), /read|configure/i);
      item.observations.deniedInspectorWithdrawsExactSnapshot = true;
      item.counts = counts();
      assert.deepEqual(item.counts, {
        gridReads: 1,
        effectCalls: 0,
        admissions: 0,
      });
      report.observations.push(item);
      delete report.inProgressCase;
      await context.close();
    }
  assert.deepEqual(
    await manifest(),
    before,
    "Product source changed during probe",
  );
  assert.deepEqual(report.unknownApi, []);
  assert.deepEqual(report.pageErrors, []);
  report.completed = true;
} catch (e) {
  report.completed = false;
  report.error = e.message;
  report.body = await browser
    ?.contexts()
    .at(-1)
    ?.pages()
    .at(-1)
    ?.locator("body")
    .innerText();
  throw e;
} finally {
  await browser?.close();
  await server.close();
  await rm(scratch, { recursive: true, force: true });
  report.cleanup = {
    browserClosed: true,
    serverClosed: true,
    temporaryCacheRemoved: true,
    sharedBackendUsed: false,
  };
  report.harnessSource = await readFile(new URL(import.meta.url), "utf8");
  await writeFile(
    process.env.OPEN_EPM_GRID_REPORT || "/tmp/openepm-ip13-grid-after.json",
    JSON.stringify(report, null, 2) + "\n",
  );
}
console.log(
  JSON.stringify(
    {
      completed: report.completed,
      caseCount: report.observations.length,
      pageErrors: report.pageErrors,
      unknownApi: report.unknownApi,
      cleanup: report.cleanup,
    },
    null,
    2,
  ),
);
