// Isolated rendered regression for App/MetadataNavigation; never contacts a product backend.
// Run: node web-ui/src/AppNavigation.browser.mjs [result.json]
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  rm,
  writeFile,
  readFile,
  stat,
} from "node:fs/promises";
import { createHash } from "node:crypto";
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
let cacheDir, wrapper, ownedIdentity, server;
const sourcePaths = [
  "src/App.tsx",
  "src/Applications.tsx",
  "src/styles.css",
  "src/AppNavigation.browser.mjs",
  "src/MetadataNavigation.tsx",
  "src/metadata-workspace.css",
  "src/metadata-navigation.ts",
  "src/Breadcrumbs.tsx",
  "src/UiIcon.tsx",
  "src/MetadataWorkspace.tsx",
  "src/CapabilityArea.tsx",
  "src/SupportingDetail.tsx",
  "src/exact-cell-mutation.tsx",
  "src/data-transfer-action.ts",
  "src/data-workspaces.css",
  "src/workspace-navigation.ts",
  "src/focused-workspaces.css",
  "src/ServerAdministration.tsx",
  "src/GlobalPanels.tsx",
  "src/MetadataRelationships.tsx",
  "src/AttributeCatalog.tsx",
  "src/metadata-data.ts",
  "src/metadata-relationships-data.ts",
  "src/api.ts",
  "src/task-list.ts",
  "src/types.ts",
  "package.json",
  "package-lock.json",
  "vite.config.ts",
];
async function sourceHashes() {
  return Object.fromEntries(
    await Promise.all(
      sourcePaths.map(async (name) => [
        name,
        createHash("sha256")
          .update(await readFile(resolve(webRoot, name)))
          .digest("hex"),
      ]),
    ),
  );
}
const application = {
  workspaceId: "fixture",
  applicationId: "navigation",
  name: "Navigation fixture",
  status: "Active",
  kind: "blank",
};
const dimensions = [
  {
    dimension_id: "Account",
    name: "Accounts",
    model_role: "Account",
    status: "Active",
  },
];
const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.dimension.list": {},
    "metadata.member.list": {},
    "application.workflow.worklist": {},
    "security.application.access.list": {},
    "security.application.effective-access.list": {},
    "security.application.dimension-policy.read": {},
    "security.application.audit.list": {},
  },
  revisions: { metadata: 7, data: 1, policy: 1, security: 1, commit: 7 },
};
const report = {
  format: "openepm-navigation-accessibility-rendered-v1",
  criterionContext: "IP-13-AC-01",
  criterionAccepted: false,
  method:
    "Chromium over actual Vite source; complete navigation-control inventory with accessible-name queries, computed visible cues and real Tab/Enter; all API traffic intercepted with disposable in-memory fixtures",
  limits: [
    "No product backend, HTTP/OIDC identity, installed MCP client or assistive-technology observation.",
    "Complete actionable navigation inventory for the fixture's Administrator shell, five workspace section owners, directory tabs, search destinations/applications and metadata view tabs. Page-specific editor checks cover Supporting detail only.",
  ],
  sourceBefore: await sourceHashes(),
  inventories: [],
  mobileModalChecks: [],
  ownerCoverage: [],
  readerNavigation: [],
  fixtureReadObservations: [],
  widths: [],
  metadataReadRecovery: null,
  sameRoleAccessRefresh: null,
  supportingDetailKeyboard: [],
  unknownApi: [],
  apiRequests: [],
  pageErrors: [],
  mutations: 0,
};
let browser, currentPage;
let stage = "setup",
  currentWidth = null;

async function verifySupportingDetailKeyboard(page, base, width) {
  const coordinate = { Account: "Sales" };
  const row = {
    members: coordinate,
    value: {
      type: "LineDetailLiteral",
      items: [{ description: "Travel", decimal: "12.50" }],
    },
    sourceRef: "fixture-closed-sales",
  };
  const reads = [];
  let previews = 0;
  let releaseCell;
  let observeCell;
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    if (path === "/api/applications")
      return route.fulfill(
        json({ applications: [application], nextAfter: null }),
      );
    if (path === "/api/session-identity")
      return route.fulfill(
        json({
          subject: "detail-fixture-editor",
          identityBinding: "a".repeat(64),
          displayIdentity: "Detail fixture editor",
          applicationMcpEndpoint: null,
        }),
      );
    if (path === "/api/runtime")
      return route.fulfill(
        json({ build: { sourceCommit: "a".repeat(40), packagedSchema: 1 } }),
      );
    if (path === "/api/platform/browser/catalog")
      return route.fulfill(json({ languageVersion: 2, functions: {} }));
    if (path === "/api/catalog")
      return route.fulfill(
        json({
          ...catalog,
          functions: {
            "facts.export.page": {},
            "facts.cube.scan": {},
            "facts.line-detail.replace": {},
          },
        }),
      );
    if (path === "/api/read") {
      const fn = body.program.function;
      const args = body.program.arguments;
      assert.equal(body.workspaceId, application.workspaceId);
      assert.equal(body.applicationId, application.applicationId);
      reads.push(fn);
      if (fn === "facts.export.page") {
        if (Object.keys(args.members).length) {
          assert.deepEqual(args.members, coordinate);
          assert.equal(args.snapshotRevision, 9);
        }
        return route.fulfill(
          json({
            result: { rows: [row], snapshotRevision: 9, nextCursor: null },
          }),
        );
      }
      if (fn === "facts.cube.scan") {
        assert.deepEqual(args.members, coordinate);
        observeCell?.();
        if (releaseCell) await releaseCell;
        return route.fulfill(
          json({
            result: {
              snapshotRevision: 9,
              rows: [
                {
                  members: coordinate,
                  kind: "numeric",
                  numericChangeId: "fixture-current",
                  amount: "12.50",
                },
              ],
            },
          }),
        );
      }
    }
    if (path === "/api/preview") {
      previews++;
      assert.deepEqual(body.program.arguments.coordinate, coordinate);
      assert.equal(
        body.program.arguments.expectedCellChangeId,
        "fixture-current",
      );
      assert.equal(
        body.program.arguments.expectedDetailChangeId,
        "fixture-current",
      );
      return route.fulfill(json({ code: "STALE_DETAIL_CHANGE_ID" }, 400));
    }
    report.unknownApi.push(path);
    report.mutations++;
    return route.abort();
  });

  const detailUrl = `${base}/#/data/0?workspace=fixture&application=navigation&section=detail`;
  await page.goto(detailUrl);
  const workspace = page.getByRole("region", {
    name: "Supporting detail",
    exact: true,
  });
  const detailList = workspace.getByRole("button", {
    name: "Read detail",
    exact: true,
  });
  const open = workspace.getByRole("button", { name: "Open", exact: true });
  const editor = workspace.getByRole("group", {
    name: "Supporting detail editor",
    exact: true,
  });
  const heading = editor.getByRole("heading", { name: "Reviewed replacement" });
  const close = editor.getByRole("button", { name: "Close detail" });
  const isFocused = (control) =>
    control.evaluate((element) => element === document.activeElement);
  await detailList.press("Enter");
  await open.waitFor();
  assert(await isFocused(detailList));
  await page.keyboard.press("Tab");
  assert(await isFocused(open));
  let settleCell;
  releaseCell = new Promise((resolve) => (settleCell = resolve));
  const seeingCell = new Promise((resolve) => (observeCell = resolve));
  await page.keyboard.press("Enter");
  await seeingCell;
  assert(await isFocused(open));
  assert.equal(await open.getAttribute("aria-disabled"), "true");
  const readStatus = workspace.getByRole("status", {
    name: "Supporting detail read status",
  });
  assert.match(await readStatus.innerText(), /Reading supporting detail/);
  settleCell();
  await heading.waitFor();
  await page.waitForFunction(
    () => document.activeElement?.textContent === "Reviewed replacement",
  );
  await page.keyboard.press("Tab");
  assert(await isFocused(close));
  await page.keyboard.press("Escape");
  await editor.waitFor({ state: "detached" });
  assert(await isFocused(open));

  await page.keyboard.press("Enter");
  await heading.waitFor();
  const add = editor.getByRole("button", { name: "Add line" });
  await add.press("Enter");
  const description = editor.getByLabel("Description", { exact: true }).last();
  assert(await isFocused(description));
  await description.fill("Fixture proposal");
  await description.press("Enter");
  assert.equal(previews, 0);
  const remove = editor.getByRole("button", { name: "Remove line 2" });
  await remove.press("Enter");
  assert(
    await isFocused(editor.getByRole("button", { name: "Remove line 1" })),
  );
  await editor
    .getByLabel("Description", { exact: true })
    .last()
    .fill("Revised travel");
  const preview = editor.getByRole("button", {
    name: "Preview exact replacement",
  });
  await preview.press("Enter");
  await workspace
    .getByRole("alert")
    .filter({
      hasText: "Reread the current values and preview the edit again.",
    })
    .waitFor();
  assert(await isFocused(preview));
  assert.equal(
    await editor.getByLabel("Description").inputValue(),
    "Revised travel",
  );
  await preview.press("Escape");
  const discard = page.getByRole("alertdialog", {
    name: "Discard unsaved changes?",
  });
  await discard.waitFor();
  await discard.getByRole("button", { name: "Keep editing" }).press("Enter");
  await discard.waitFor({ state: "detached" });
  assert(await isFocused(preview));
  assert.equal(
    await editor.getByLabel("Description").inputValue(),
    "Revised travel",
  );
  await close.press("Enter");
  await discard
    .getByRole("button", { name: "Discard and continue" })
    .press("Enter");
  await editor.waitFor({ state: "detached" });
  assert(await isFocused(open));
  assert.equal(previews, 1);
  assert.deepEqual(reads, [
    "facts.export.page",
    "facts.cube.scan",
    "facts.export.page",
    "facts.cube.scan",
    "facts.export.page",
  ]);
  report.supportingDetailKeyboard.push({
    width,
    pendingFocusRetained: true,
    enteredAndReturned: true,
    conflictPreservedDraftAndFocus: true,
    guardedDiscardReturnedFocus: true,
    previews,
  });
}
const expectedSidebar = [
  "Home",
  "Applications",
  "My Work",
  "Server Administration",
  "Choose application; current Navigation fixture",
  "Overview",
  "Grid",
  "Data",
  "Flows",
  "Monitor",
  "Metadata",
  "Rules",
  "Users & Security",
  "Administration",
];
const expectedMetadata = [
  "Collapse metadata navigation",
  "Dimensions",
  "Collapse Accounts metadata",
  "Members",
  "Relationships",
  "Tree",
  "Attributes",
  "Security tags",
  "Properties & access",
  "Member Lists",
  "Function reference",
];
// BEGIN navigation owner fixture contracts (also exercised without a browser).
const coverageApplications = [
  application,
  {
    workspaceId: "fixture",
    applicationId: "planning",
    name: "Planning fixture",
    status: "Active",
    kind: "blank",
  },
];
const workspaceOwners = [
  {
    page: "data",
    name: "Data workspaces",
    controls: [
      "Import",
      "Export",
      "Supporting detail",
      "Recent activity",
      "Function reference",
    ],
  },
  {
    page: "rules",
    name: "Rules workspaces",
    controls: [
      "Python programs",
      "Calculation rules",
      "Calculated members",
      "Schedules",
      "Execution authorities",
      "Program schedules",
      "Function reference",
    ],
  },
  {
    page: "lists",
    name: "Member Lists workspaces",
    controls: ["Member lists", "Function reference"],
  },
  {
    page: "security",
    name: "Users & Security workspaces",
    controls: [
      "Users & access",
      "Effective access",
      "Dimensional policy",
      "Security audit",
      "Function reference",
    ],
  },
  {
    page: "administration",
    name: "Administration workspaces",
    controls: ["Application state", "Function reference"],
  },
];
const searchDestinations = [
  "Home",
  "Applications",
  "My Work",
  "Server Administration",
  "Overview",
  "Grid",
  "Data",
  "Metadata",
  "Member Lists",
  "Rules",
  "Flows",
  "Tasks",
  "Monitor",
  "Users & Security",
  "Administration",
];
const platformReads = {
  "identity.native-user.list": { offset: 0, limit: 100 },
  "identity.group.list": { offset: 0, limit: 100 },
  "identity.group.membership.list": {
    afterGroupId: null,
    afterSubjectId: null,
    limit: 100,
  },
};
function memberReadFixture(coverageEnabled) {
  if (!coverageEnabled)
    return {
      result: { rows: [], nextAfterMemberId: null, metadataRevision: 7 },
    };
  return {
    languageVersion: 2,
    function: "metadata.member.list",
    result: {
      dimensionId: "Account",
      rows: [
        {
          dimension_id: "Account",
          member_id: "fixture-account",
          name: "Fixture account",
          status: "Active",
          short_description: "",
          detailed_description: "",
          numeric_value_kind: null,
          aggregation_operator: "Add",
          custom_values: {},
        },
      ],
      nextAfterMemberId: null,
      metadataRevision: 7,
      hasMore: false,
    },
  };
}
function ownerCoverageRead(path, method, body) {
  assert.equal(method, "POST", "NAVIGATION_FIXTURE_READ_METHOD");
  const fn = body?.program?.function;
  if (Object.hasOwn(platformReads, fn || "")) {
    assert.equal(
      path,
      "/api/platform/browser/read",
      "NAVIGATION_FIXTURE_READ_ROUTE",
    );
    assert.deepEqual(
      body,
      {
        program: {
          languageVersion: 2,
          function: fn,
          arguments: platformReads[fn],
        },
      },
      "NAVIGATION_FIXTURE_READ_PROGRAM",
    );
    return fn === "identity.group.membership.list"
      ? { items: [], nextAfter: null }
      : { items: [], nextOffset: null };
  }
  const args =
    fn === "metadata.relationship.list"
      ? { dimension: "Account", limit: 100 }
      : fn === "metadata.attribute-definition.list"
        ? body?.program?.arguments?.scope === "Relationship"
          ? {
              scope: "Relationship",
              dimensionId: "Account",
              status: "Active",
              limit: 200,
            }
          : body?.program?.arguments?.status === "Active"
            ? {
                scope: "Member",
                dimensionId: "Account",
                status: "Active",
                limit: 200,
              }
            : { scope: "Member", dimensionId: "Account", limit: 100 }
        : null;
  assert.ok(args, "NAVIGATION_FIXTURE_READ_FUNCTION");
  assert.equal(path, "/api/read", "NAVIGATION_FIXTURE_READ_ROUTE");
  assert.deepEqual(
    body,
    {
      workspaceId: "fixture",
      applicationId: "navigation",
      program: { languageVersion: 2, function: fn, arguments: args },
    },
    "NAVIGATION_FIXTURE_READ_PROGRAM",
  );
  return {
    languageVersion: 2,
    function: fn,
    result: {
      rows: [],
      metadataRevision: 7,
      dimensionId: "Account",
      hasMore: false,
      ...(fn === "metadata.relationship.list"
        ? {
            hierarchyId: "fixture-account-default",
            status: null,
            nextAfterRelationshipId: null,
            nextCursor: null,
          }
        : { scope: args.scope, nextAfterAttributeId: null }),
    },
  };
}
function validateCoverageRequest(path, method, body) {
  assert.equal(method, "POST", "NAVIGATION_FIXTURE_READ_METHOD");
  if (path === "/api/platform/browser/catalog") {
    assert.deepEqual(body, {}, "NAVIGATION_FIXTURE_CATALOG_PROGRAM");
    return;
  }
  if (path === "/api/platform/browser/read") {
    ownerCoverageRead(path, method, body);
    return;
  }
  assert.ok(
    coverageApplications.some(
      (app) =>
        app.workspaceId === body?.workspaceId &&
        app.applicationId === body?.applicationId,
    ),
    "NAVIGATION_FIXTURE_SCOPE",
  );
  const scope = {
    workspaceId: body.workspaceId,
    applicationId: body.applicationId,
  };
  if (path === "/api/catalog") {
    assert.deepEqual(body, scope, "NAVIGATION_FIXTURE_CATALOG_PROGRAM");
    return;
  }
  if (path === "/api/tasks") {
    assert.deepEqual(
      body,
      { ...scope, afterSequence: 0, limit: 100, attentionOnly: false },
      "NAVIGATION_FIXTURE_TASK_READ_PROGRAM",
    );
    return;
  }
  assert.equal(path, "/api/read", "NAVIGATION_FIXTURE_READ_ROUTE");
  const fn = body.program?.function;
  const args =
    fn === "metadata.dimension.list" || fn === "application.workflow.worklist"
      ? { limit: 100 }
      : fn === "metadata.member.list"
        ? { dimension: "Account", limit: 100, expectedMetadataRevision: 7 }
        : null;
  if (args)
    assert.deepEqual(
      body,
      {
        ...scope,
        program: { languageVersion: 2, function: fn, arguments: args },
      },
      "NAVIGATION_FIXTURE_READ_PROGRAM",
    );
  else ownerCoverageRead(path, method, body);
}
function assertOwnerInventory(entries, labels) {
  assert.deepEqual(
    entries.map((entry) => entry.destinationLabel).sort(),
    [...labels].sort(),
    "NAVIGATION_OWNER_INVENTORY_CHANGED",
  );
  for (const entry of entries) {
    assert.ok(
      entry.name.includes(entry.destinationLabel),
      "NAVIGATION_OWNER_NAME_MISSING_DESTINATION",
    );
    assert.ok(
      entry.text.includes(entry.destinationLabel),
      "NAVIGATION_OWNER_CUE_MISSING_DESTINATION",
    );
  }
}
function assertOwnerCoverage(records, reads, widths) {
  for (const width of widths) {
    const current = records.filter((record) => record.width === width);
    for (const [name, count] of [
      ...workspaceOwners.map((owner) => [owner.page, owner.controls.length]),
      ["directory", 3],
      ["metadata-views", 4],
    ]) {
      const match = current.filter((record) => record.owner === name);
      assert.equal(match.length, 1, "NAVIGATION_OWNER_PHASE_MISSING");
      assert.equal(
        match[0].controls,
        count,
        "NAVIGATION_OWNER_PHASE_INCOMPLETE",
      );
    }
    const search = current.filter((record) => record.owner === "search");
    assert.deepEqual(
      search.map((record) => record.state).sort(),
      (width <= 650
        ? ["mobile-closed"]
        : ["expanded", "manual-collapsed"]
      ).sort(),
      "NAVIGATION_SEARCH_STATES_INCOMPLETE",
    );
    for (const record of search) {
      assert.deepEqual(
        [...record.destinations].sort(),
        [...searchDestinations].sort(),
        "NAVIGATION_SEARCH_INVENTORY_INCOMPLETE",
      );
      assert.deepEqual(
        record.applications,
        coverageApplications.map((app) => app.name),
        "NAVIGATION_SEARCH_APPLICATIONS_INCOMPLETE",
      );
    }
    assert.equal(
      current.length,
      7 + search.length,
      "NAVIGATION_OWNER_PHASE_UNEXPECTED",
    );
    assert.deepEqual(
      [
        ...new Set(
          reads
            .filter((read) => read.width === width)
            .map((read) => read.function),
        ),
      ].sort(),
      [
        ...Object.keys(platformReads),
        "metadata.relationship.list",
        "metadata.attribute-definition.list",
      ].sort(),
      "NAVIGATION_OWNER_READS_INCOMPLETE",
    );
  }
}
// END navigation owner fixture contracts.

const shellSelector =
  "nav button, nav a[href], [role=tablist] [role=tab], .application-switcher, .sidebar-close, .menu-button, .top-actions > button, .skip-link";
// Observe the frame after focus/hover style invalidation has been rendered.
// Two animation frames are a browser-paint boundary, not a timed retry/sleep.
async function settleRenderedFocus(page) {
  await page.evaluate(
    () =>
      new Promise((done) =>
        requestAnimationFrame(() => requestAnimationFrame(() => done(null))),
      ),
  );
}
// Playwright's role selector models ARIA names/visibility in JavaScript; the
// installed engine does not treat inert as hidden. Use Chromium's actual AX
// tree for modal background exclusion, mapped to exact DOM backend identities.
function mobileAccessibilityObservation(root, nodes) {
  const background = new Set(),
    roots = [],
    modal = [],
    close = [];
  function visit(node, inheritedBackground = false) {
    const values = node.attributes || [];
    const attrs = new Map();
    for (let i = 0; i < values.length; i += 2)
      attrs.set(values[i], values[i + 1]);
    const classes = (attrs.get("class") || "").split(/\s+/);
    const region = classes.includes("topbar")
      ? "topbar"
      : classes.includes("skip-link")
        ? "skip-link"
        : attrs.get("id") === "main-content"
          ? "main"
          : null;
    if (region) {
      roots.push(region);
      assert.ok(attrs.has("inert"), "NAVIGATION_BACKGROUND_NOT_INERT");
    }
    const inBackground = inheritedBackground || Boolean(region);
    if (inBackground) {
      assert.ok(
        Number.isInteger(node.backendNodeId) && node.backendNodeId > 0,
        "NAVIGATION_AX_DOM_ID_MISSING",
      );
      background.add(node.backendNodeId);
    }
    if (attrs.get("id") === "primary-navigation")
      modal.push(node.backendNodeId);
    if (classes.includes("sidebar-close")) close.push(node.backendNodeId);
    for (const child of node.children || []) visit(child, inBackground);
  }
  visit(root);
  assert.deepEqual(
    roots.sort(),
    ["main", "skip-link", "topbar"],
    "NAVIGATION_BACKGROUND_REGIONS_MISSING",
  );
  assert.equal(modal.length, 1, "NAVIGATION_AX_MODAL_DOM_MISSING");
  assert.equal(close.length, 1, "NAVIGATION_AX_CLOSE_DOM_MISSING");
  assert.ok(
    nodes.every((node) => typeof node.ignored === "boolean"),
    "NAVIGATION_AX_STATE_MALFORMED",
  );
  const exposed = nodes.filter((node) => node.ignored === false);
  assert.equal(
    exposed.filter((node) => background.has(node.backendDOMNodeId)).length,
    0,
    "NAVIGATION_BACKGROUND_AX_EXPOSED",
  );
  assert.equal(
    exposed.filter(
      (node) =>
        node.backendDOMNodeId === modal[0] &&
        node.role?.value === "dialog" &&
        node.name?.value === "Application navigation",
    ).length,
    1,
    "NAVIGATION_MODAL_AX_MISSING",
  );
  assert.equal(
    exposed.filter(
      (node) =>
        node.backendDOMNodeId === close[0] &&
        node.role?.value === "button" &&
        node.name?.value === "Close sidebar",
    ).length,
    1,
    "NAVIGATION_CLOSE_AX_MISSING",
  );
  return {
    backgroundRegions: roots,
    backgroundDomNodes: background.size,
    exposedBackgroundNodes: 0,
    modalExposed: true,
    closeExposed: true,
  };
}

async function inspectMobileAccessibility(page) {
  const session = await page.context().newCDPSession(page);
  try {
    await session.send("Accessibility.enable");
    const { root } = await session.send("DOM.getDocument", { depth: -1 });
    const { nodes } = await session.send("Accessibility.getFullAXTree");
    return mobileAccessibilityObservation(root, nodes);
  } finally {
    await session.detach();
  }
}

async function inventory(page, state, width, owner = null) {
  stage = "inventory-" + state;
  // Each inventory owns its exact keyboard identifiers; previous views/queries
  // cannot accidentally satisfy a later destination's Tab observation.
  await page.locator("[data-navigation-proof-id]").evaluateAll((elements) => {
    for (const element of elements)
      element.removeAttribute("data-navigation-proof-id");
  });
  const controls = page.locator(owner?.selector || shellSelector);
  const entries = [];
  const inertControls = [];
  const modalOpen =
    (await page.locator(".sidebar[aria-modal=true]").count()) === 1;
  for (let index = 0; index < (await controls.count()); index++) {
    const control = controls.nth(index);
    if (!(await control.isVisible()) || !(await control.isEnabled())) continue;
    if (await control.evaluate((el) => Boolean(el.closest("[inert]")))) {
      assert.ok(modalOpen, "NAVIGATION_UNEXPECTED_INERT_CONTROL");
      assert.equal(
        await control.evaluate((el) => Boolean(el.closest(".sidebar"))),
        false,
        "NAVIGATION_MODAL_SOURCE_INERT",
      );
      inertControls.push(
        (await control.getAttribute("aria-label")) ||
          (await control.innerText()).replace(/\s+/g, " ").trim(),
      );
      continue;
    }
    const identity = "navigation-proof-" + index;
    await control.evaluate(
      (el, id) => el.setAttribute("data-navigation-proof-id", id),
      identity,
    );
    const name =
      (await control.getAttribute("aria-label")) ||
      (await control.innerText()).replace(/\s+/g, " ").trim();
    const role = await control.evaluate(
      (el) =>
        el.getAttribute("role") || (el.tagName === "A" ? "link" : "button"),
    );
    report.currentControl = { identity, name, role, state, width };
    report.observedCue = null;
    assert.ok(name, "NAVIGATION_NAME_EMPTY");
    assert.equal(
      await page.getByRole(role, { name, exact: true }).and(control).count(),
      1,
      "NAVIGATION_ACCESSIBLE_NAME_MISMATCH",
    );
    await control.scrollIntoViewIfNeeded();
    await control.focus();
    if (await control.evaluate((el) => el.matches(".top-actions > button")))
      await control.hover();
    await settleRenderedFocus(page);
    const cue = await control.evaluate((el) => {
      const box = el.getBoundingClientRect(),
        style = getComputedStyle(el),
        pseudo = getComputedStyle(el, "::after");
      const text = el.innerText.replace(/\s+/g, " ").trim();
      const adjacent = el.matches(".metadata-navigation-toggle")
        ? el.parentElement.querySelector("button:first-child")?.innerText.trim()
        : "";
      return {
        text,
        adjacent,
        focus: {
          isActiveElement: el === document.activeElement,
          matchesFocus: el.matches(":focus"),
          matchesFocusVisible: el.matches(":focus-visible"),
          documentHasFocus: document.hasFocus(),
          inertAncestor: Boolean(el.closest("[inert]")),
          activeElement: document.activeElement
            ? {
                tag: document.activeElement.tagName,
                className: String(document.activeElement.className),
                ariaLabel: document.activeElement.getAttribute("aria-label"),
              }
            : null,
        },
        bounds: {
          x: box.x,
          y: box.y,
          width: box.width,
          height: box.height,
          top: box.top,
          bottom: box.bottom,
          left: box.left,
          right: box.right,
        },
        css: {
          top: style.top,
          left: style.left,
          position: style.position,
          transform: style.transform,
          visibility: style.visibility,
        },
        shell: {
          className: document.querySelector(".shell")?.className,
          inert: Boolean(document.querySelector(".shell")?.inert),
          ariaHidden: document
            .querySelector(".shell")
            ?.getAttribute("aria-hidden"),
          browserStatePresent: Boolean(
            document.querySelector(".browser-state"),
          ),
        },
        topbar: el.matches(".top-actions > button"),
        tooltip:
          pseudo.display !== "none" ? pseudo.content.replace(/^"|"$/g, "") : "",
        inViewport:
          box.width > 0 &&
          box.height > 0 &&
          box.right > 0 &&
          box.left < innerWidth &&
          box.bottom > 0 &&
          box.top < innerHeight,
        visible: style.visibility === "visible" && style.display !== "none",
        unobscured: el.contains(
          document.elementFromPoint(
            Math.max(0, Math.min(innerWidth - 1, box.left + box.width / 2)),
            Math.max(0, Math.min(innerHeight - 1, box.top + box.height / 2)),
          ),
        ),
        sidebar: !!el.closest(".sidebar"),
      };
    });
    report.observedCue = cue;
    assert.ok(
      cue.visible && cue.inViewport && cue.unobscured,
      "NAVIGATION_CONTROL_NOT_REACHABLE",
    );
    assert.ok(
      /[A-Za-z]/.test(cue.text + cue.adjacent + cue.tooltip),
      "NAVIGATION_VISUAL_CUE_MISSING",
    );
    if (cue.topbar)
      assert.equal(cue.tooltip, name, "NAVIGATION_ACTION_CUE_MISMATCH");
    if (
      name === "Choose application; current Navigation fixture" &&
      state.includes("collapsed") &&
      width > 650
    )
      assert.ok(
        cue.text.includes("Choose application"),
        "NAVIGATION_APPLICATION_CUE_MISSING",
      );
    const destinationLabel = owner
      ? owner.labelSelector
        ? (await control.locator(owner.labelSelector).innerText()).trim()
        : name
      : null;
    entries.push({
      identity,
      name,
      role,
      ...cue,
      ...(owner ? { destinationLabel } : {}),
    });
  }
  const collapsed = await page
    .locator(".shell")
    .evaluate((el) => el.classList.contains("collapsed"));
  const expected =
    collapsed && width <= 650
      ? []
      : [
          ...expectedSidebar,
          ...(!collapsed ? expectedMetadata : []),
          ...(!collapsed && width <= 650 ? ["Close sidebar"] : []),
        ];
  if (!owner)
    assert.deepEqual(
      entries
        .filter((x) => x.sidebar)
        .map((x) => x.name)
        .sort(),
      expected.sort(),
      "NAVIGATION_SIDEBAR_INVENTORY_CHANGED",
    );
  if (modalOpen) {
    assert.ok(inertControls.length > 0, "NAVIGATION_BACKGROUND_NOT_ISOLATED");
    assert.ok(
      entries.every((entry) => entry.sidebar),
      "NAVIGATION_MODAL_BACKGROUND_ACTIONABLE",
    );
  }
  if (owner) assertOwnerInventory(entries, owner.labels);
  // Actual sequential keyboard navigation, including CSS/off-canvas exclusion.
  await page.evaluate(() => {
    document.body.tabIndex = -1;
    document.body.focus();
  });
  if (owner?.keyboardStart) await page.locator(owner.keyboardStart).focus();
  const reached = new Set();
  for (let step = 0; step < 200 && reached.size < entries.length; step++) {
    await page.keyboard.press("Tab");
    await settleRenderedFocus(page);
    const focused = await page.evaluate(() => {
      const el = document.activeElement;
      if (!(el instanceof HTMLElement)) return null;
      if (el.closest("[inert]"))
        throw new Error("NAVIGATION_TAB_REACHED_INERT_BACKGROUND");
      if (
        document.querySelector(".sidebar[aria-modal=true]") &&
        !el.closest(".sidebar")
      )
        throw new Error("NAVIGATION_TAB_ESCAPED_MODAL");
      const id = el.getAttribute("data-navigation-proof-id"),
        b = el.getBoundingClientRect();
      const pseudo = getComputedStyle(el, "::after");
      return id
        ? {
            id,
            visible:
              getComputedStyle(el).visibility === "visible" &&
              b.right > 0 &&
              b.left < innerWidth &&
              b.bottom > 0 &&
              b.top < innerHeight,
            topbar: el.matches(".top-actions > button"),
            focusVisible: el.matches(":focus-visible"),
            name: el.getAttribute("aria-label"),
            tooltip:
              pseudo.display !== "none"
                ? pseudo.content.replace(/^"|"$/g, "")
                : "",
          }
        : null;
    });
    if (focused && entries.some((entry) => entry.identity === focused.id)) {
      report.currentControl = {
        ...entries.find((entry) => entry.identity === focused.id),
        state,
        width,
        keyboard: true,
      };
      report.observedCue = focused;
      assert.ok(focused.visible, "NAVIGATION_TAB_REACHED_HIDDEN_CONTROL");
      assert.ok(focused.focusVisible, "NAVIGATION_TAB_FOCUS_CUE_MISSING");
      if (focused.topbar)
        assert.equal(
          focused.tooltip,
          focused.name,
          "NAVIGATION_KEYBOARD_ACTION_CUE_MISMATCH",
        );
      reached.add(focused.id);
    }
  }
  await page.evaluate(() => document.body.removeAttribute("tabindex"));
  assert.deepEqual(
    [...reached].sort(),
    entries.map((x) => x.identity).sort(),
    "NAVIGATION_KEYBOARD_INVENTORY_INCOMPLETE",
  );
  report.inventories.push({
    width,
    state,
    controls: entries,
    inertBackgroundControls: inertControls,
    keyboardReached: reached.size,
    ...(owner ? { owner: owner.name } : {}),
  });
  return entries;
}
async function mainNavigationStates(page, width, callback) {
  const toggle = page.getByRole("button", {
    name: /^(Expand|Collapse) sidebar$/,
  });
  if (width <= 650) {
    const close = page.getByRole("button", {
      name: "Close sidebar",
      exact: true,
    });
    if (await close.isVisible()) await close.click();
    await callback("mobile-closed");
    return;
  }
  if (await page.locator(".shell.collapsed").count()) await toggle.click();
  await page.locator(".shell:not(.collapsed)").waitFor();
  await callback("expanded");
  await page
    .getByRole("button", { name: "Collapse sidebar", exact: true })
    .click();
  await page.locator(".shell.collapsed").waitFor();
  await callback("manual-collapsed");
}

async function verifyReaderNavigation(page, base, width) {
  const scoped = (pageName) =>
    `${base}/ui/#/${pageName}/0?workspace=fixture&application=navigation`;
  await page.route("**/api/**", async (route) => {
    const { pathname: path } = new URL(route.request().url());
    const method = route.request().method();
    if (method === "GET") {
      if (path === "/api/applications")
        return route.fulfill(
          json({ applications: coverageApplications, nextAfter: null }),
        );
      if (path === "/api/session-identity")
        return route.fulfill(
          json({
            subject: "navigation-reader",
            displayIdentity: "Navigation Reader",
            identityBinding: "a".repeat(64),
          }),
        );
      if (path === "/api/runtime")
        return route.fulfill(
          json({ build: { sourceCommit: "a".repeat(40), packagedSchema: 1 } }),
        );
    }
    if (method === "POST") {
      const body = route.request().postDataJSON();
      if (path === "/api/platform/browser/catalog")
        return route.fulfill(json({ languageVersion: 2, functions: {} }));
      assert.ok(
        coverageApplications.some(
          (app) =>
            app.workspaceId === body.workspaceId &&
            app.applicationId === body.applicationId,
        ),
        "NAVIGATION_READER_SCOPE",
      );
      if (path === "/api/catalog")
        return route.fulfill(
          json({
            ...catalog,
            applicationAccess: {
              role: "Reader",
              workspaceAdministrator: false,
            },
            functions: { "application.workflow.worklist": {} },
          }),
        );
      if (path === "/api/tasks")
        return route.fulfill(
          json({ tasks: [], hasMore: false, nextSequence: null }),
        );
      if (
        path === "/api/read" &&
        body.program?.function === "application.workflow.worklist"
      )
        return route.fulfill(
          json({ result: { items: [], hasMore: false, nextAfter: null } }),
        );
    }
    report.unknownApi.push(path);
    report.mutations++;
    return route.abort();
  });

  async function check(pageName, cases) {
    stage = "reader-" + pageName;
    await page.goto(scoped(pageName));
    await page.locator(cases[0].selector).first().waitFor();
    await mainNavigationStates(page, width, async (state) => {
      for (const owner of cases) {
        const entries = await inventory(
          page,
          `reader-${pageName}-${state}`,
          width,
          owner,
        );
        report.readerNavigation.push({
          width,
          state,
          page: pageName,
          controls: entries.map((entry) => entry.destinationLabel),
        });
      }
    });
  }

  await check("home", [
    {
      name: "home-application",
      selector: ".home-page .hero-card > button",
      labels: ["Open application"],
    },
    {
      name: "home-work",
      selector: ".home-page .section-title > button",
      labels: ["My work"],
    },
    {
      name: "reader-home-shortcuts",
      selector: ".home-page .action-grid .action-card",
      labelSelector: "strong",
      labels: [
        "Explore data",
        "Data tools",
        "Follow a workflow",
        "Inspect activity",
      ],
    },
  ]);
  await page
    .getByRole("button", { name: "Open application", exact: true })
    .press("Enter");
  await page.waitForURL(/#\/overview\//);

  await check("overview", [
    {
      name: "overview-grid",
      selector: ".overview-page .page-heading button",
      labels: ["Open Grid →"],
    },
    {
      name: "reader-overview-shortcuts",
      selector: ".overview-page .journey-list .action-card",
      labelSelector: "strong",
      labels: ["Open cube grid", "Review flows"],
    },
    {
      name: "overview-monitor",
      selector: ".overview-activity .section-title button",
      labels: ["Open Monitor"],
    },
  ]);
  await page
    .getByRole("button", { name: "Open Monitor", exact: true })
    .press("Space");
  await page.waitForURL(/#\/monitor\//);

  await check("applications", [
    {
      name: "reader-applications",
      selector: ".application-card-open",
      labelSelector: "strong",
      labels: coverageApplications.map((app) => app.name),
    },
  ]);
  await page
    .getByRole("button", { name: "Open Planning fixture", exact: true })
    .press("Enter");
  await page.waitForURL(/#\/overview\/.*application=planning/);
  await page.waitForFunction(
    () => document.activeElement?.id === "main-content",
    undefined,
    { timeout: 5000 },
  );
}

async function extendedNavigationOwners(page, base, width) {
  const scoped = (target, query = "") =>
    base +
    "/ui/?navigationCoverage=1#/" +
    target +
    "/0?workspace=fixture&application=navigation" +
    query;
  const inventoryRegion = async (name, selector, labels, state, extra = {}) => {
    await inventory(page, "owner-" + name + "-" + state, width, {
      name,
      selector,
      labels,
      ...extra,
    });
  };
  for (const owner of workspaceOwners) {
    stage = "loading-workspace-" + owner.page;
    await page.goto(scoped(owner.page, "&section=reference"));
    const nav = page.getByRole("navigation", { name: owner.name, exact: true });
    await nav.waitFor();
    await nav
      .getByRole("button", { name: "Function reference", exact: true })
      .waitFor();
    await mainNavigationStates(page, width, (state) =>
      inventoryRegion(
        owner.page,
        `nav[aria-label="${owner.name}"] button`,
        owner.controls,
        state,
      ),
    );
    // Explicit keyboard route activation in each owner. Returning to Reference
    // avoids invoking editor effects; unavailable editors remain honest.
    const first = nav.getByRole("button", {
      name: owner.controls[0],
      exact: true,
    });
    await first.focus();
    await page.keyboard.press("Enter");
    await page.waitForFunction(
      (name) =>
        document.querySelector(
          'nav.workspace-section-nav button[aria-current="page"]',
        )?.textContent === name,
      owner.controls[0],
    );
    const firstRoute = new URL(page.url()).hash;
    assert.ok(
      !firstRoute.includes("section=reference"),
      "NAVIGATION_OWNER_ROUTE_UNCHANGED",
    );
    await nav
      .getByRole("button", { name: "Function reference", exact: true })
      .focus();
    await page.keyboard.press("Space");
    await page.waitForFunction(
      () =>
        new URLSearchParams(location.hash.split("?")[1]).get("section") ===
        "reference",
    );
    report.ownerCoverage.push({
      width,
      owner: owner.page,
      controls: owner.controls.length,
      enterDestination: owner.controls[0],
      spaceReturn: "Function reference",
    });
  }
  stage = "loading-directory-navigation";
  await page.goto(base + "/ui/?navigationCoverage=1#/server/0?section=users");
  const directory = page.getByRole("navigation", {
    name: "Directory workspaces",
    exact: true,
  });
  await directory.waitFor();
  await mainNavigationStates(page, width, (state) =>
    inventoryRegion(
      "directory",
      'nav[aria-label="Directory workspaces"] button',
      ["Users", "Groups", "Membership"],
      state,
    ),
  );
  for (const [label, section] of [
    ["Groups", "groups"],
    ["Membership", "membership"],
    ["Users", "users"],
  ]) {
    await directory.getByRole("button", { name: label, exact: true }).focus();
    await page.keyboard.press("Enter");
    await page.waitForFunction(
      (expected) =>
        new URLSearchParams(location.hash.split("?")[1]).get("section") ===
        expected,
      section,
    );
    await directory
      .getByRole("button", { name: label, exact: true })
      .and(page.locator('[aria-current="page"]'))
      .waitFor();
  }
  report.ownerCoverage.push({
    width,
    owner: "directory",
    controls: 3,
    keyboardDestinations: ["groups", "membership", "users"],
  });

  stage = "loading-manage-attributes";
  await page.goto(
    scoped("metadata", "&metadataSection=relationships&dimension=Account"),
  );
  const metadata = page.getByRole("navigation", {
    name: "Accounts metadata views",
    exact: true,
  });
  await metadata.waitFor();
  await mainNavigationStates(page, width, (state) =>
    inventoryRegion(
      "metadata-views",
      'nav[aria-label="Accounts metadata views"] button',
      ["Members", "Relationships", "Tree", "Manage attributes"],
      state,
    ),
  );
  await metadata
    .getByRole("button", { name: "Manage attributes", exact: true })
    .focus();
  await page.keyboard.press("Enter");
  await page
    .getByRole("heading", { name: "Attribute definitions", exact: true })
    .waitFor();
  assert.equal(
    new URLSearchParams(new URL(page.url()).hash.split("?")[1]).get(
      "metadataSection",
    ),
    "attributes",
    "NAVIGATION_ATTRIBUTE_ROUTE_MISMATCH",
  );
  report.ownerCoverage.push({
    width,
    owner: "metadata-views",
    controls: 4,
    keyboardDestination: "attributes",
  });

  stage = "loading-global-search";
  await page.goto(scoped("overview"));
  await page.getByRole("button", { name: "Search", exact: true }).waitFor();
  await mainNavigationStates(page, width, async (state) => {
    await page.getByRole("button", { name: "Search", exact: true }).click();
    const panel = page.getByRole("dialog", {
      name: "Search Open EPM",
      exact: true,
    });
    await panel.waitFor();
    const input = panel.getByRole("textbox", {
      name: "Search applications, pages or authorized functions",
      exact: true,
    });
    const seen = new Set();
    for (const query of ["a", "o", "i", "r"]) {
      await input.fill(query);
      const expected = searchDestinations.filter((name) =>
        name.toLowerCase().includes(query),
      );
      const group = panel.locator(".result-group").filter({
        has: page.getByRole("heading", { name: "Destinations", exact: true }),
      });
      await group.getByRole("button").first().waitFor();
      const entries = await inventory(
        page,
        "owner-search-" + state + "-" + query,
        width,
        {
          name: "search-destinations",
          selector:
            '#global-search-panel .result-group:has(h3:text-is("Destinations")) > button',
          labels: expected,
          labelSelector: "strong",
          keyboardStart: "#global-search-panel input",
        },
      );
      for (const entry of entries) seen.add(entry.destinationLabel);
    }
    assert.deepEqual(
      [...seen].sort(),
      [...searchDestinations].sort(),
      "NAVIGATION_SEARCH_INVENTORY_INCOMPLETE",
    );
    await input.fill("fixture");
    await inventoryRegion(
      "search-applications",
      '#global-search-panel .result-group:has(h3:text-is("Applications")) > button',
      coverageApplications.map((app) => app.name),
      state,
      { labelSelector: "strong", keyboardStart: "#global-search-panel input" },
    );
    await page.keyboard.press("Escape");
    await panel.waitFor({ state: "hidden" });
    report.ownerCoverage.push({
      width,
      owner: "search",
      state,
      destinations: [...seen],
      applications: coverageApplications.map((app) => app.name),
    });
  });
  // A real search destination and application selection use the same visible
  // results and normal keyboard handlers after their full inventory checks.
  for (const [query, label, target] of [
    ["administration", "Administration", "administration"],
    ["planning fixture", "Planning fixture", "overview"],
  ]) {
    await page.getByRole("button", { name: "Search", exact: true }).click();
    const panel = page.getByRole("dialog", {
      name: "Search Open EPM",
      exact: true,
    });
    await panel.getByRole("textbox").fill(query);
    const result = panel
      .locator(".result-group > button")
      .filter({ has: page.getByText(label, { exact: true }) });
    await result.focus();
    await page.keyboard.press("Enter");
    await panel.waitFor({ state: "hidden" });
    await page.waitForFunction(
      (expected) => location.hash.startsWith("#/" + expected + "/"),
      target,
    );
    if (label === "Planning fixture")
      await page
        .locator(
          '.application-switcher[aria-label="Choose application; current Planning fixture"]',
        )
        .waitFor({ state: "attached" });
    if (label === "Planning fixture")
      await page.waitForFunction(
        () =>
          location.hash ===
          "#/overview/1?workspace=fixture&application=planning",
      );
  }
}

const json = (body, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});
try {
  cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-ui-navigation-"));
  ownedIdentity = await stat(cacheDir);
  await mkdir(resolve(cacheDir, "node_modules"));
  wrapper = resolve(cacheDir, "qualification.vite.config.mjs");
  await writeFile(
    wrapper,
    `import original from ${JSON.stringify(resolve(webRoot, "vite.config.ts"))};\nexport default async env => {const c=await(typeof original==="function"?original(env):original);return {...c,root:${JSON.stringify(webRoot)},cacheDir:${JSON.stringify(resolve(cacheDir, "vite-cache"))}};};\n`,
  );
  server = await createServer({
    root: webRoot,
    configFile: wrapper,
    cacheDir: resolve(cacheDir, "vite-cache"),
    server: { host: "127.0.0.1", port: 0 },
    clearScreen: false,
    logLevel: "error",
  });
  await server.listen();
  const base = "http://127.0.0.1:" + server.httpServer.address().port;
  browser = await chromium.launch({ headless: true });
  report.browserVersion = browser.version();
  const detailOnly = process.argv[3] === "--supporting-detail";
  const readerOnly = process.argv[3] === "--reader-navigation";
  const widths = detailOnly
    ? []
    : readerOnly
      ? process.argv[4] === "--width"
        ? [Number(process.argv[5])]
        : [650, 651, 684, 950, 951]
      : process.argv[3] === "--width"
        ? [Number(process.argv[4])]
        : [650, 651, 684, 700, 701, 950, 951, 1280];
  if (detailOnly) {
    report.criterionContext = "IP-13-AC-02";
    report.method =
      "Chromium over actual Vite App and Supporting detail source using keyboard controls and isolated API fixtures";
    report.limits = [
      "No product backend, live identity service or assistive-technology observation.",
      "Focus, draft and conflict state are scoped to the Supporting detail editor.",
    ];
  }
  if (readerOnly) {
    report.limits = [
      "Reader Home, Overview and Applications destinations through fixture-backed Browser source.",
      "The fixture uses an isolated API and Chromium without assistive technology.",
    ];
  }
  assert.ok(
    widths.every((width) =>
      [650, 651, 684, 700, 701, 950, 951, 1280].includes(width),
    ),
    "NAVIGATION_WIDTH_INVALID",
  );
  for (const width of widths) {
    currentWidth = width;
    stage = "loading";
    const page = await browser.newPage({
      viewport: { width, height: 908 },
      reducedMotion: "reduce",
    });
    currentPage = page;
    page.on("pageerror", (error) => report.pageErrors.push(error.message));
    if (readerOnly) {
      await verifyReaderNavigation(page, base, width);
      report.widths.push({ width, role: "Reader" });
      await page.close();
      currentPage = null;
      continue;
    }
    let coverageEnabled = false;
    let accessContext = "a".repeat(64);
    let dimensionReply;
    let platformReply;
    let releaseDimensions;
    const heldRead = new Promise((resolveRead) => {
      releaseDimensions = resolveRead;
    });
    await page.route("**/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      report.apiRequests.push(path);
      const method = route.request().method();
      const getPaths = [
        "/api/applications",
        "/api/session-identity",
        "/api/runtime",
      ];
      const postPaths = [
        "/api/catalog",
        "/api/platform/browser/catalog",
        "/api/tasks",
        "/api/read",
        ...(coverageEnabled ? ["/api/platform/browser/read"] : []),
      ];
      if (
        !(
          (method === "GET" && getPaths.includes(path)) ||
          (method === "POST" && postPaths.includes(path))
        )
      ) {
        report.mutations++;
        report.unknownApi.push(path);
        return route.abort();
      }
      if (coverageEnabled && method === "POST") {
        try {
          validateCoverageRequest(path, method, route.request().postDataJSON());
        } catch {
          report.unknownApi.push(path + ":COVERAGE_REQUEST_CONTRACT");
          return route.fulfill(
            json({ error: "UNEXPECTED_FIXTURE_REQUEST_CONTRACT" }, 400),
          );
        }
      }
      if (path === "/api/applications")
        return route.fulfill(
          json({
            applications: coverageEnabled
              ? coverageApplications
              : [application],
            nextAfter: null,
          }),
        );
      if (path === "/api/session-identity")
        return route.fulfill(
          json({
            subject: "fixture-reader",
            identityBinding: "a".repeat(64),
            displayIdentity: "Fixture reader",
            applicationMcpEndpoint: null,
          }),
        );
      if (path === "/api/runtime")
        return route.fulfill(
          json({
            readOnlyReview: true,
            build: { sourceCommit: "a".repeat(40), packagedSchema: 1 },
          }),
        );
      if (path === "/api/platform/browser/catalog")
        return route.fulfill(
          platformReply
            ? await platformReply
            : json({
                languageVersion: 2,
                functions: coverageEnabled
                  ? Object.fromEntries(
                      Object.keys(platformReads).map((name) => [name, {}]),
                    )
                  : {},
              }),
        );
      if (path === "/api/catalog")
        return route.fulfill(
          json({
            ...catalog,
            accessContext,
            ...(coverageEnabled
              ? {
                  functions: {
                    ...catalog.functions,
                    "metadata.relationship.list": {},
                    "metadata.attribute-definition.list": {},
                  },
                }
              : {}),
          }),
        );
      if (coverageEnabled && method === "POST") {
        const body = route.request().postDataJSON();
        const fn = body?.program?.function;
        if (
          path === "/api/platform/browser/read" ||
          Object.hasOwn(platformReads, fn || "") ||
          [
            "metadata.relationship.list",
            "metadata.attribute-definition.list",
          ].includes(fn)
        ) {
          try {
            const response = ownerCoverageRead(path, method, body);
            report.fixtureReadObservations.push({ width, path, function: fn });
            return route.fulfill(json(response));
          } catch {
            report.unknownApi.push(path + ":COVERAGE_READ_CONTRACT");
            return route.fulfill(
              json({ error: "UNEXPECTED_FIXTURE_READ_CONTRACT" }, 400),
            );
          }
        }
      }
      if (path === "/api/tasks")
        return route.fulfill(
          json({
            tasks: [
              {
                taskId: "done-1",
                sequence: 2,
                function: "fixture.completed",
                status: "Succeeded",
                progressState: "succeeded",
              },
              {
                taskId: "done-2",
                sequence: 1,
                function: "fixture.completed",
                status: "Succeeded",
                progressState: "succeeded",
              },
            ],
            hasMore: true,
            nextSequence: 1,
          }),
        );
      if (path === "/api/read") {
        const fn = route.request().postDataJSON().program.function;
        if (fn === "metadata.dimension.list") {
          await heldRead;
          if (dimensionReply) return route.fulfill(await dimensionReply);
          return route.fulfill(
            json({
              result: {
                rows: dimensions,
                nextAfterDimensionId: null,
                metadataRevision: 7,
              },
            }),
          );
        }
        if (fn === "metadata.member.list")
          return route.fulfill(json(memberReadFixture(coverageEnabled)));
        if (fn === "application.workflow.worklist")
          return route.fulfill(
            json({ result: { items: [], nextCursor: null } }),
          );
      }
      report.mutations++;
      report.unknownApi.push(path);
      return route.fulfill(json({ error: "UNEXPECTED_FIXTURE_REQUEST" }, 400));
    });
    await page.route("**/*", (route) =>
      new URL(route.request().url()).origin === base
        ? route.fallback()
        : route.abort(),
    );
    await page.goto(
      base +
        "/ui/#/metadata/0?workspace=fixture&application=navigation&metadataSection=members&dimension=Account",
    );
    stage = "loading-dimensions";
    await page
      .getByRole("option", { name: "Loading dimensions…", exact: true })
      .waitFor({ state: "attached" });
    assert.equal(
      await page
        .getByRole("option", { name: "Dimension unavailable", exact: true })
        .count(),
      0,
    );
    releaseDimensions();
    stage = "loading-dimensions-completion";
    await page
      .getByRole("option", { name: "Accounts", exact: true })
      .waitFor({ state: "attached" });
    stage = "loading-platform-navigation";
    // Readiness is DOM existence: a closed off-canvas sidebar is correctly
    // absent from the accessibility tree. Actual inventory queries stay strict.
    await page
      .getByRole("navigation", {
        name: "Global navigation",
        includeHidden: true,
      })
      .getByRole("button", {
        name: "Server Administration",
        exact: true,
        includeHidden: true,
      })
      .waitFor({ state: "attached" });
    const navigation = page.locator(".metadata-navigation");
    if (width <= 950) {
      await inventory(page, "initial-collapsed", width);
      assert.equal(
        await page
          .getByRole("button", { name: "Expand sidebar", exact: true })
          .getAttribute("aria-expanded"),
        "false",
      );
      const railLabelOnScreen = await navigation
        .locator(".metadata-navigation-compact-label")
        .evaluate((el) => {
          const box = el.getBoundingClientRect();
          return box.width > 0 && box.right > 0 && box.left < innerWidth;
        });
      assert.equal(railLabelOnScreen, width > 650);
      assert.equal(
        await navigation.locator(".metadata-navigation-items").count(),
        0,
      );
      await page
        .getByRole("button", { name: "Expand sidebar", exact: true })
        .focus();
      await page.keyboard.press("Space");
    }
    await navigation
      .getByRole("button", { name: "Members", exact: true })
      .waitFor({ state: "visible" });
    const visibleNames = await navigation
      .locator(".metadata-navigation-items button b")
      .evaluateAll((labels) =>
        labels.map((label) => ({
          text: label.textContent,
          visible:
            getComputedStyle(label).display !== "none" &&
            label.getBoundingClientRect().width > 0 &&
            label.getBoundingClientRect().height > 0,
        })),
      );
    assert.ok(visibleNames.length >= 9);
    assert.ok(
      visibleNames.every((label) => label.visible && label.text.trim()),
    );
    if (width <= 650) {
      stage = "mobile-modal-focus-and-isolation";
      const modal = page.getByRole("dialog", {
        name: "Application navigation",
        exact: true,
      });
      assert.equal(await modal.count(), 1);
      const close = modal.getByRole("button", {
        name: "Close sidebar",
        exact: true,
      });
      assert.ok(
        await close.evaluate((el) => el === document.activeElement),
        "NAVIGATION_MODAL_INITIAL_FOCUS",
      );
      assert.equal(await page.locator(".sidebar-scrim").isVisible(), true);
      assert.deepEqual(
        await page
          .locator(".topbar, main, .skip-link")
          .evaluateAll((nodes) => nodes.map((el) => el.inert)),
        [true, true, true],
      );
      report.mobileModalAccessibility = {
        roleSelectorCount: await page
          .getByRole("button", { name: "Collapse sidebar", exact: true })
          .count(),
        method:
          "Chromium CDP full AX tree with exact DOM backend identities; role selector count is diagnostic only",
      };
      Object.assign(
        report.mobileModalAccessibility,
        await inspectMobileAccessibility(page),
      );
      const refusal = await page.locator(".menu-button").evaluate((el) => {
        const previous = document.activeElement;
        el.focus();
        return {
          inertAncestor: Boolean(el.closest("[inert]")),
          focusUnchanged: document.activeElement === previous,
          stillClose:
            document.activeElement?.classList.contains("sidebar-close"),
        };
      });
      report.mobileModalAccessibility.backgroundFocusRefusal = refusal;
      assert.deepEqual(
        refusal,
        { inertAncestor: true, focusUnchanged: true, stillClose: true },
        "NAVIGATION_BACKGROUND_FOCUSABLE",
      );
      await page.keyboard.press("Shift+Tab");
      const last = modal.getByRole("button").last();
      assert.ok(
        await last.evaluate((el) => el === document.activeElement),
        "NAVIGATION_MODAL_REVERSE_WRAP",
      );
      await page.keyboard.press("Tab");
      assert.ok(
        await close.evaluate((el) => el === document.activeElement),
        "NAVIGATION_MODAL_FORWARD_WRAP",
      );
      await page.keyboard.press("Escape");
      const menu = page.getByRole("button", {
        name: "Expand sidebar",
        exact: true,
      });
      assert.ok(
        await menu.evaluate((el) => el === document.activeElement),
        "NAVIGATION_MODAL_ESCAPE_RETURN",
      );
      assert.deepEqual(
        await page
          .locator(".topbar, main, .skip-link")
          .evaluateAll((nodes) => nodes.map((el) => el.inert)),
        [false, false, false],
      );
      await page.keyboard.press("Space");
      assert.ok(await close.evaluate((el) => el === document.activeElement));
      await page.setViewportSize({ width: 651, height: 908 });
      await settleRenderedFocus(page);
      await menu.waitFor();
      assert.ok(
        await menu.evaluate((el) => el === document.activeElement),
        "NAVIGATION_MODAL_RESIZE_RETURN",
      );
      assert.equal(await page.locator(".sidebar[aria-modal=true]").count(), 0);
      assert.deepEqual(
        await page
          .locator(".topbar, main, .skip-link")
          .evaluateAll((nodes) => nodes.map((el) => el.inert)),
        [false, false, false],
      );
      await page.setViewportSize({ width, height: 908 });
      await settleRenderedFocus(page);
      await menu.click();
      await close.waitFor();
      assert.ok(await close.evaluate((el) => el === document.activeElement));
      report.mobileModalChecks.push({
        width,
        initialCloseFocus: true,
        backgroundInert: true,
        backgroundExcludedFromAccessibleControls: true,
        forwardAndReverseTabWrap: true,
        escapeRestoresMenu: true,
        resizeRestoresMenuAndBackground: true,
      });
    }
    await inventory(page, "expanded", width);
    // Disclosures keep focus while removing and restoring their descendants.
    const metadataToggle = navigation.getByRole("button", {
      name: "Collapse metadata navigation",
      exact: true,
    });
    await metadataToggle.focus();
    await page.keyboard.press("Enter");
    assert.equal(
      await navigation.locator(".metadata-navigation-items").count(),
      0,
      "NAVIGATION_METADATA_COLLAPSE_FAILED",
    );
    const reopenMetadata = navigation.getByRole("button", {
      name: "Expand metadata navigation",
      exact: true,
    });
    assert.ok(
      await reopenMetadata.evaluate((el) => el === document.activeElement),
      "NAVIGATION_DISCLOSURE_FOCUS_LOST",
    );
    await page.keyboard.press("Space");
    await navigation
      .getByRole("button", { name: "Members", exact: true })
      .waitFor({ state: "visible" });
    const dimensionToggle = navigation.getByRole("button", {
      name: "Collapse Accounts metadata",
      exact: true,
    });
    await dimensionToggle.focus();
    await page.keyboard.press("Space");
    assert.equal(
      await navigation
        .getByRole("button", { name: "Members", exact: true })
        .count(),
      0,
      "NAVIGATION_DIMENSION_COLLAPSE_FAILED",
    );
    await page.keyboard.press("Enter");
    await navigation
      .getByRole("button", { name: "Members", exact: true })
      .waitFor({ state: "visible" });
    if (width === 1280) {
      await navigation
        .getByRole("button", { name: "Members", exact: true })
        .focus();
      await page.setViewportSize({ width: 684, height: 908 });
      const expand = page.getByRole("button", {
        name: "Expand sidebar",
        exact: true,
      });
      await expand.waitFor();
      assert.equal(
        await expand.evaluate((el) => el === document.activeElement),
        true,
      );
      await page.setViewportSize({ width, height: 908 });
      // Growing the viewport does not silently override the current collapsed choice.
      await expand.click();
      await page.setViewportSize({ width: 684, height: 908 });
      await expand.waitFor();
      await page
        .getByRole("navigation", { name: "Global navigation" })
        .getByRole("button", { name: "Applications", exact: true })
        .focus();
      await page.setViewportSize({ width: 650, height: 908 });
      await settleRenderedFocus(page);
      assert.equal(
        await expand.evaluate((el) => el === document.activeElement),
        true,
        "NAVIGATION_MOBILE_FOCUS_RETURN",
      );
      await page.setViewportSize({ width, height: 908 });
      await expand.click();
      report.resizeAcrossBreakpoint =
        "Collapsed at684px with safe focus; explicit expansion at1280px restored labels";
    }
    const reference = navigation.getByRole("button", {
      name: "Function reference",
      exact: true,
    });
    await reference.focus();
    await page.keyboard.press("Enter");
    await page
      .getByRole("heading", { name: "Function reference", exact: true })
      .waitFor();
    if (width <= 950) {
      assert.equal(
        await page
          .getByRole("button", { name: "Expand sidebar", exact: true })
          .evaluate((el) => el === document.activeElement),
        true,
      );
      await page
        .getByRole("button", { name: "Expand sidebar", exact: true })
        .click();
    }
    // Manual collapse also removes descendants and preserves a visible destination cue.
    await page
      .getByRole("button", {
        name: width <= 650 ? "Close sidebar" : "Collapse sidebar",
        exact: true,
      })
      .click();
    assert.equal(
      await navigation.locator(".metadata-navigation-items").count(),
      0,
    );
    if (width <= 650)
      assert.equal(
        await page
          .getByRole("button", { name: "Expand sidebar", exact: true })
          .evaluate((el) => el === document.activeElement),
        true,
      );
    await inventory(page, "manual-collapsed", width);
    stage = "manual-reopen-sidebar";
    await page
      .getByRole("button", { name: "Expand sidebar", exact: true })
      .click();
    const reopenedDimensions = navigation.getByRole("button", {
      name: "Dimensions",
      exact: true,
    });
    await reopenedDimensions.waitFor({ state: "visible" });
    assert.equal(
      await reopenedDimensions.isVisible(),
      true,
      "NAVIGATION_MANUAL_REOPEN_DIMENSIONS_MISSING",
    );
    stage = "overview-zero-count-readiness";
    await page.goto(
      base + "/ui/#/overview/0?workspace=fixture&application=navigation",
    );
    await page
      .getByText(/Their progress and attention counts are unknown/)
      .waitFor();
    for (const label of ["In progress", "Needs attention"]) {
      assert.equal(
        await page
          .locator(".metric")
          .filter({ has: page.getByText(label, { exact: true }) })
          .locator("strong")
          .innerText(),
        "0",
        "NAVIGATION_OVERVIEW_ZERO_COUNT_MISMATCH",
      );
    }
    if (width === 1280) {
      const dimensionStatus = page.getByRole("heading", {
        name: /^This dimension is (inactive|unavailable)$/,
      });
      const pendingDimensions = async () => {
        await page
          .getByText("Loading the current metadata snapshot…", { exact: true })
          .waitFor();
        assert.equal(await dimensionStatus.count(), 0);
      };
      const dimensionPage = (rows) =>
        json({
          result: { rows, nextAfterDimensionId: null, metadataRevision: 7 },
        });
      const interruptedResponse = Promise.withResolvers();
      dimensionReply = interruptedResponse.promise;
      stage = "metadata-read-interrupted";
      await page.goto(
        base +
          "/ui/#/metadata/0?workspace=fixture&application=navigation&metadataSection=members&dimension=Archive",
      );
      await pendingDimensions();
      interruptedResponse.resolve(
        json({ code: "METADATA_READ_INTERRUPTED" }, 500),
      );
      await page
        .getByText("The model could not be refreshed.", { exact: true })
        .waitFor();
      assert.equal(await dimensionStatus.count(), 0);

      stage = "metadata-read-confirms-absence";
      const absentResponse = Promise.withResolvers();
      dimensionReply = absentResponse.promise;
      await page.getByRole("button", { name: "Refresh", exact: true }).click();
      await pendingDimensions();
      absentResponse.resolve(dimensionPage(dimensions));
      await page
        .getByRole("heading", {
          name: "This dimension is unavailable",
          exact: true,
        })
        .waitFor();

      stage = "metadata-read-recovers";
      const readyResponse = Promise.withResolvers();
      dimensionReply = readyResponse.promise;
      await page.getByRole("button", { name: "Refresh", exact: true }).click();
      await pendingDimensions();
      readyResponse.resolve(
        dimensionPage([
          ...dimensions,
          {
            ...dimensions[0],
            dimension_id: "Archive",
            name: "Archive accounts",
          },
        ]),
      );
      await page
        .getByRole("option", { name: "Archive accounts", exact: true })
        .waitFor({ state: "attached" });
      assert.equal(await dimensionStatus.count(), 0);
      dimensionReply = undefined;
      report.metadataReadRecovery = {
        width,
        abandonedStatusDuringRetry: true,
        availableAfterRetry: true,
      };
      stage = "metadata-same-role-access-refresh";
      const narrowedResponse = Promise.withResolvers();
      dimensionReply = narrowedResponse.promise;
      accessContext = "b".repeat(64);
      await page.evaluate(() => window.dispatchEvent(new Event("online")));
      await pendingDimensions();
      assert.equal(
        await page
          .getByRole("option", { name: "Archive accounts", exact: true })
          .count(),
        0,
      );
      narrowedResponse.resolve(dimensionPage(dimensions));
      await page
        .getByRole("heading", {
          name: "This dimension is unavailable",
          exact: true,
        })
        .waitFor();
      assert.match(new URL(page.url()).hash, /dimension=Archive/);
      dimensionReply = undefined;
      report.sameRoleAccessRefresh = {
        width,
        oldNameWithdrawnBeforeRead: true,
        routeRetained: true,
      };

      stage = "platform-catalogue-gateway-refusal";
      coverageEnabled = true;
      await page.goto(base + "/ui/#/server/0?section=groups");
      const directory = page.getByRole("heading", {
        name: "Identity directory",
        exact: true,
      });
      const denial = page.getByText(
        "Your current account does not have server administration access.",
        { exact: true },
      );
      const blocked = page.getByRole("heading", {
        name: "Revalidating your session",
        exact: true,
      });
      const recheck = async () => {
        const request = page.waitForRequest((request) =>
          request.url().endsWith("/api/platform/browser/catalog"),
        );
        await page.evaluate(() => window.dispatchEvent(new Event("online")));
        await request;
        await blocked.waitFor();
        assert.equal(await page.locator(".shell").getAttribute("inert"), "");
      };
      await directory.waitFor();
      const refusal = Promise.withResolvers();
      platformReply = refusal.promise;
      await recheck();
      assert.equal(await denial.count(), 0);
      refusal.resolve(json({ error: "WEB_ORIGIN_REQUIRED" }, 403));
      await page
        .getByText("Open EPM could not confirm server administration access.", {
          exact: true,
        })
        .waitFor();
      assert.equal(await denial.count(), 0);
      assert.equal(await directory.count(), 0);

      stage = "platform-catalogue-keyboard-retry";
      const restored = Promise.withResolvers();
      platformReply = restored.promise;
      const retry = page.getByRole("button", { name: "Retry access check" });
      await retry.focus();
      await page.keyboard.press("Enter");
      await blocked.waitFor();
      assert.equal(await retry.count(), 0);
      assert.equal(await denial.count(), 0);
      restored.resolve(
        json({ languageVersion: 2, authorized: true, functions: {} }),
      );
      await directory.waitFor();
      assert.match(new URL(page.url()).hash, /section=groups$/);

      stage = "platform-catalogue-confirmed-denial";
      const revoked = Promise.withResolvers();
      platformReply = revoked.promise;
      await recheck();
      assert.equal(await denial.count(), 0);
      revoked.resolve(
        json({ languageVersion: 2, authorized: false, functions: {} }),
      );
      await denial.waitFor();
      assert.equal(await retry.count(), 0);
      assert.equal(await directory.count(), 0);
      platformReply = undefined;
      await page.evaluate(() => window.dispatchEvent(new Event("online")));
      await directory.waitFor();
      report.platformCatalogueRecheck = {
        width,
        gatewayRefusalWasIncompleteCheck: true,
        keyboardRetryWithInertShell: true,
        sameRouteRecovered: true,
        explicitDenialSettledSeparately: true,
      };
    }
    coverageEnabled = true;
    await extendedNavigationOwners(page, base, width);
    report.widths.push({
      width,
      initialCollapse: width <= 950,
      visibleMetadataLabels: visibleNames.length,
      manualExpandCollapse: "passed",
      keyboardRouteAndFocus: "passed",
      loadingState: "passed",
      boundedZeroCounts: "passed",
    });
    await page.close();
    currentPage = null;
  }
  if (!detailOnly && !readerOnly)
    assertOwnerCoverage(
      report.ownerCoverage,
      report.fixtureReadObservations,
      widths,
    );
  stage = "supporting-detail-keyboard";
  for (const width of readerOnly ? [] : [651, 1280]) {
    currentWidth = width;
    currentPage = await browser.newPage({ viewport: { width, height: 908 } });
    currentPage.on("pageerror", (error) =>
      report.pageErrors.push(error.message),
    );
    await verifySupportingDetailKeyboard(currentPage, base, width);
    await currentPage.close();
    currentPage = null;
  }
  assert.deepEqual(report.unknownApi, []);
  assert.deepEqual(report.pageErrors, []);
  assert.equal(report.mutations, 0);
  report.sourceAfter = await sourceHashes();
  assert.deepEqual(
    report.sourceAfter,
    report.sourceBefore,
    "NAVIGATION_SOURCE_DRIFT",
  );
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.failure = {
    stage,
    width: currentWidth,
    code:
      String(error.message).match(/NAVIGATION_[A-Z_]+/)?.[0] ||
      "NAVIGATION_ASSERTION_FAILED",
  };
  process.exitCode = 1;
  if (currentPage && !currentPage.isClosed() && process.argv[2]) {
    try {
      const screenshot = await currentPage.screenshot({
        animations: "disabled",
      });
      const path = process.argv[2].replace(/\.json$/, "") + "-failure.png";
      await writeFile(path, screenshot, { flag: "wx" });
      report.failureScreenshot = {
        path,
        sha256: createHash("sha256").update(screenshot).digest("hex"),
        bytes: screenshot.length,
      };
    } catch {
      report.failureScreenshotError = "NAVIGATION_FIXTURE_SCREENSHOT_FAILED";
    }
  }
} finally {
  report.cleanup = {
    browserClosed: false,
    serverClosed: false,
    ownedCacheRemoved: false,
  };
  report.cleanupFailures = [];
  report.ownedCache = cacheDir
    ? {
        path: cacheDir,
        device: ownedIdentity?.dev,
        inode: ownedIdentity?.ino,
        uid: ownedIdentity?.uid,
      }
    : null;
  try {
    await browser?.close();
    report.cleanup.browserClosed = true;
  } catch {
    report.cleanupFailures.push("NAVIGATION_BROWSER_CLOSE_FAILED");
  }
  try {
    await server?.close();
    report.cleanup.serverClosed = true;
  } catch {
    report.cleanupFailures.push("NAVIGATION_SERVER_CLOSE_FAILED");
  }
  if (!cacheDir) report.cleanup.ownedCacheRemoved = true;
  else if (report.cleanup.browserClosed && report.cleanup.serverClosed) {
    try {
      const current = await stat(cacheDir);
      assert.equal(current.dev, ownedIdentity.dev);
      assert.equal(current.ino, ownedIdentity.ino);
      assert.equal(current.uid, ownedIdentity.uid);
      await rm(cacheDir, { recursive: true });
      report.cleanup.ownedCacheRemoved = true;
    } catch {
      report.cleanupFailures.push("NAVIGATION_CACHE_CLEANUP_REFUSED");
    }
  }
  if (!Object.values(report.cleanup).every(Boolean)) {
    report.status = "failed";
    process.exitCode = 1;
  }
  if (process.argv[2])
    await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n", {
      flag: "wx",
    });
}
console.log(JSON.stringify(report, null, 2));
