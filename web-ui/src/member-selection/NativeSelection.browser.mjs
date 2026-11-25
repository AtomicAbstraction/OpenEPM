// Current picker in real Chromium. Every API call is intercepted; this creates
// no product metadata, named selections, facts or authentication state.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
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
const sources = [
  "src/member-selection/MemberSelectionDialog.tsx",
  "src/member-selection/NativeSelection.browser.mjs",
  "src/member-selection/member-selection.css",
  "src/member-selection/native-selection.ts",
  "src/member-selection/selection-types.ts",
  "src/api.ts",
  "src/styles.css",
  "package-lock.json",
  "vite.config.ts",
];
async function captureSources() {
  return Object.fromEntries(
    await Promise.all(
      sources.map(async (name) => [
        name,
        createHash("sha256")
          .update(await readFile(resolve(webRoot, name)))
          .digest("hex"),
      ]),
    ),
  );
}
const app = {
  workspaceId: "fixture",
  applicationId: "selection",
  name: "Selection fixture",
  status: "Active",
};
const catalog = {
  applicationAccess: {
    issuer: "fixture",
    subjectId: "selector",
    role: "Reader",
    workspaceAdministrator: false,
  },
  revisions: { metadata: 7, data: 1, policy: 1, security: 1, commit: 1 },
  functions: {
    "metadata.hierarchy.list": {},
    "metadata.member.select": {},
    "metadata.member_list.list": {},
    "metadata.member_list.read": {},
  },
  enabledCapabilities: [],
};
const savedList = {
  listId: "europe-business",
  dimensionId: "Entity",
  name: "European operations",
  status: "Active",
  active: true,
  executable: true,
  stateToken: "b".repeat(64),
  canonicalDigest: "c".repeat(64),
  definition: null,
};
const memberRows = [
  ["World", "World"],
  ["Europe", "Region"],
  ["Other", "Region"],
  ["CH", "Switzerland"],
].map(([member_id, name]) => ({
  member_id,
  name,
  status: "Active",
  short_description: "Fixture member",
}));
const initial = {
  kind: "inline_expression",
  expressionFormat: "openepm-member-list-expression-v1",
  expression: {
    kind: "navigation",
    operation: "descendants",
    scope: "hierarchy",
    hierarchyId: "primary",
    anchor: { memberId: "Europe", pathRelationshipIds: ["world-europe"] },
    includeSelf: false,
    allParents: false,
  },
};
const exclusion = {
  kind: "attribute",
  attributeId: "Status",
  operator: "eq",
  value: "Closed",
};
const request = {
  dimensionId: "Entity",
  dimensionName: "Entity",
  metadataRevision: 7,
  initial,
  initialExclude: exclusion,
  cardinality: { kind: "one-or-more", maximum: 100 },
  capability: {
    allowExplicitMembers: true,
    allowNativeBrowse: true,
    allowHierarchySelector: true,
    allowNamedMemberList: true,
    allowAttributeSelector: false,
    allowInlineExpression: true,
    allowExclusion: false,
    orderMatters: true,
  },
};
const entry = `import React,{useState} from 'react'; import {createRoot} from 'react-dom/client'; import {MemberSelectionDialog} from '/src/member-selection/MemberSelectionDialog.tsx'; import '/src/styles.css';
  window.fixture={applied:[],original:${JSON.stringify(request)}};
  const saved=new URLSearchParams(location.search).has('saved');
  const request=${JSON.stringify(request)};
  const members=${JSON.stringify(memberRows)};
  if(saved) request.initial={kind:'members',memberIds:['CH']};
  function Harness(){const[open,setOpen]=useState(false); return React.createElement('main',null,React.createElement('button',{onClick:()=>setOpen(true)},'Choose entities'),open&&React.createElement(MemberSelectionDialog,{app:${JSON.stringify(app)},catalog:${JSON.stringify(catalog)},request,members:saved?members.filter(member=>member.member_id!=='CH'):members,onCancel:()=>setOpen(false),onApply:(result)=>{window.fixture.applied.push(result);setOpen(false)}}));}createRoot(document.getElementById('root')).render(React.createElement(Harness));`;
const report = {
  method:
    "Actual current MemberSelectionDialog/CSS in Chromium with all API calls mocked",
  cases: [],
  pageErrors: [],
  unexpectedApi: [],
  apiFunctions: [],
  sourceBefore: await captureSources(),
};
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-selection-ui-"));
const cacheIdentity = await stat(cacheDir);
let server,
  browser,
  page,
  mode = "normal",
  lookup,
  lookupStarted,
  held;
const reply = (route, result, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(status === 200 ? { result } : { error: result }),
  });
try {
  const configFile = resolve(cacheDir, "qualification.vite.config.mjs");
  const viteCache = resolve(cacheDir, "vite-cache");
  await mkdir(resolve(cacheDir, "node_modules"));
  await writeFile(
    configFile,
    `import original from ${JSON.stringify(resolve(webRoot, "vite.config.ts"))};
export default async env => {
  const config = await (typeof original === "function" ? original(env) : original);
  return { ...config, root: ${JSON.stringify(webRoot)}, cacheDir: ${JSON.stringify(viteCache)} };
};\n`,
  );
  server = await createServer({
    root: webRoot,
    configFile,
    cacheDir: viteCache,
    server: { host: "127.0.0.1", port: 0 },
    clearScreen: false,
    logLevel: "error",
    plugins: [
      {
        name: "isolated-selection-fixture",
        resolveId(id) {
          if (id === "virtual:selection-fixture") return "\0selection-fixture";
        },
        load(id) {
          if (id === "\0selection-fixture") return entry;
        },
      },
    ],
  });
  await server.listen();
  browser = await playwright.chromium.launch({ headless: true });
  report.browser = browser.version();
  page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on("pageerror", (error) => report.pageErrors.push(error.message));
  await page.route(/\/selection-fixture\.html(?:\?saved)?$/, async (route) =>
    route.fulfill({
      contentType: "text/html",
      body: await server.transformIndexHtml(
        "/selection-fixture.html",
        '<!doctype html><html><head><title>Isolated selection fixture</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/@id/virtual:selection-fixture"></script></body></html>',
      ),
    }),
  );
  await page.route("**/api/**", async (route) => {
    const body = route.request().postDataJSON();
    const fn = body?.program?.function;
    if (!fn) {
      report.unexpectedApi.push(new URL(route.request().url()).pathname);
      return reply(route, "UNEXPECTED_API", 400);
    }
    report.apiFunctions.push(fn);
    if (fn === "metadata.member_list.list")
      return reply(route, {
        memberLists: [savedList],
        nextAfterListId: null,
        collectionToken: "d".repeat(64),
      });
    if (fn === "metadata.member_list.read") {
      assert.equal(body.program.arguments.listId, savedList.listId);
      return reply(route, {
        ...savedList,
        definition: { operator: "explicit", parameters: [] },
        currentMetadataRevision: 7,
        policyRevision: 1,
      });
    }
    if (fn === "metadata.hierarchy.list") {
      if (mode === "loading") {
        held = route;
        return;
      }
      return reply(route, {
        dimensionId: "Entity",
        metadataRevision: 7,
        rows: [
          {
            hierarchyId: "primary",
            name: "Management",
            status: "Active",
            membershipMode: "all_active",
            isDefault: true,
            stateToken: "a".repeat(64),
            builtMetadataRevision: 7,
            current: true,
          },
        ],
        hasMore: false,
        nextAfterId: null,
      });
    }
    if (fn === "metadata.member.select") {
      if (mode === "denied")
        return reply(route, "METADATA_SELECTION_SCOPE_UNAVAILABLE", 403);
      const { expression, resultMode } = body.program.arguments;
      if (mode === "saved" && expression.kind === "explicit") {
        assert.deepEqual(expression.memberIds, ["CH"]);
        assert.deepEqual(body.program.arguments.selectionContext, {
          expectedToken: "a".repeat(64),
        });
        assert.equal(body.program.arguments.expectedMetadataRevision, 7);
        assert.equal(body.program.arguments.expectedSecurityRevision, 1);
        assert.equal(body.program.arguments.expectedPolicyRevision, 1);
        lookup = route;
        lookupStarted();
        return;
      }
      if (mode === "stale" && expression.operation === "leaf_descendants") {
        assert.deepEqual(body.program.arguments.selectionContext, {
          expectedToken: "a".repeat(64),
        });
        return reply(route, "METADATA_SELECTION_CONTEXT_STALE", 409);
      }
      const paths = [
        ["World", [], ["World"]],
        ["Europe", ["world-europe"], ["World", "Europe"]],
        ["Other", ["world-other"], ["World", "Other"]],
        ["CH", ["world-europe", "europe-ch"], ["World", "Europe", "CH"]],
        ["CH", ["world-other", "other-ch"], ["World", "Other", "CH"]],
      ];
      const rows =
        expression.operation === "all"
          ? paths
              .filter(([id]) => mode !== "saved" || id !== "CH")
              .map(([memberId, pathRelationshipIds, pathMemberIds]) => ({
                memberId,
                name: memberRows.find((row) => row.member_id === memberId).name,
                status: "Active",
                shortDescription: "Fixture member",
                ...(resultMode === "placements"
                  ? { pathRelationshipIds, pathMemberIds }
                  : {}),
              }))
          : [];
      return reply(route, {
        dimensionId: "Entity",
        metadataRevision: 7,
        resultKind:
          expression.operation === "top"
            ? "scope"
            : (resultMode ?? "unique_member"),
        rows,
        hasMore: mode === "saved" && expression.operation === "all",
        nextCursor:
          mode === "saved" && expression.operation === "all"
            ? "later-page"
            : null,
        selectionContextToken: "a".repeat(64),
        scope: {
          kind: "scope",
          scope: expression.scope,
          hierarchyId: expression.hierarchyId,
          dimensionId: "Entity",
          name: "Entity",
          shortDescription: "",
          semanticDescription: "Structural scope top",
          businessCoordinate: false,
          supportedOperations: [
            "top",
            "all",
            "leaf_descendants",
            "parents",
            "children",
          ],
        },
      });
    }
    report.unexpectedApi.push(fn);
    return reply(route, "UNEXPECTED_API", 400);
  });
  const url = server.resolvedUrls.local[0] + "selection-fixture.html";
  await page.goto(url);
  const trigger = page.getByRole("button", { name: "Choose entities" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  async function assertKeyboardWrap() {
    const close = dialog.getByRole("button", {
      name: "Close member selection",
    });
    await close.focus();
    await page.keyboard.press("Shift+Tab");
    assert.equal(
      await dialog.evaluate((element) =>
        element.contains(document.activeElement),
      ),
      true,
    );
    await page.keyboard.press("Tab");
    assert.equal(
      await close.evaluate((element) => element === document.activeElement),
      true,
    );
  }
  await dialog
    .getByText('Excludes: Status equals "Closed"', { exact: true })
    .waitFor();
  await dialog
    .getByText(/placement World \(World\) \/ Region \(Europe\)/)
    .first()
    .waitFor();
  await dialog
    .getByRole("button", {
      name: "Collapse Region (Europe) · World / Europe [world-europe]",
    })
    .click();
  assert.equal(
    await dialog
      .getByRole("button", {
        name: "Collapse Region (Other) · World / Other [world-other]",
      })
      .getAttribute("aria-expanded"),
    "true",
  );
  await dialog
    .getByRole("button", {
      name: "Expand Region (Europe) · World / Europe [world-europe]",
    })
    .click();
  const close = dialog.getByRole("button", { name: "Close member selection" });
  await close.focus();
  await page.keyboard.press("Shift+Tab");
  assert.equal(
    await dialog
      .getByRole("button", { name: "Apply selection" })
      .evaluate((el) => el === document.activeElement),
    true,
  );
  await page.keyboard.press("Tab");
  assert.equal(
    await close.evaluate((el) => el === document.activeElement),
    true,
  );
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await trigger.evaluate((el) => el === document.activeElement),
    true,
  );
  assert.deepEqual(await page.evaluate(() => window.fixture.applied), []);
  assert.deepEqual(await page.evaluate(() => window.fixture.original), request);
  report.cases.push({
    name: "Pinned placement and exclusion remain readable; Tab wraps, Escape cancels unchanged and restores caller focus",
    status: "passed",
  });
  mode = "loading";
  await trigger.click();
  await dialog.getByText("Loading selection context…").waitFor();
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await trigger.evaluate((el) => el === document.activeElement),
    true,
  );
  await held?.abort().catch(() => {});
  held = null;
  report.cases.push({
    name: "Escape cancels an unresolved discovery read and restores focus without applying",
    status: "passed",
  });
  mode = "denied";
  await trigger.click();
  await dialog
    .getByText(
      "Hierarchy browsing is unavailable in this context. Close and reopen the selection to retry.",
    )
    .waitFor();
  assert.equal(
    await dialog
      .getByText("No placements were returned for this hierarchy.")
      .count(),
    0,
  );
  await assertKeyboardWrap();
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await trigger.evaluate((el) => el === document.activeElement),
    true,
  );
  report.cases.push({
    name: "Denied hierarchy read retains keyboard containment and returns focus to the caller",
    wrappedTabOrder: true,
    callerFocusRestored: true,
    status: "passed",
  });
  mode = "normal";
  await trigger.click();
  await dialog
    .getByRole("button", {
      name: "Use Switzerland as starting point · World / Other / CH [world-other / other-ch]",
    })
    .click();
  await dialog.getByRole("button", { name: "Base descendants" }).click();
  await dialog
    .getByText(
      "This is a complete empty result. Keeping the dynamic rule does not select the whole dimension.",
    )
    .waitFor();
  await assertKeyboardWrap();
  await dialog
    .getByRole("button", { name: "Replace selection with this dynamic rule" })
    .click();
  await dialog
    .getByRole("button", { name: "Replace selection", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Apply selection" }).click();
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await trigger.evaluate((element) => element === document.activeElement),
    true,
  );
  const [applied] = await page.evaluate(() => window.fixture.applied);
  assert.equal(applied.include.kind, "inline_expression");
  assert.equal(applied.include.expression.operation, "leaf_descendants");
  assert.deepEqual(applied.include.expression.anchor.pathRelationshipIds, [
    "world-other",
    "other-ch",
  ]);
  assert.deepEqual(applied.exclude, exclusion);
  report.cases.push({
    name: "Empty dynamic preview retains keyboard containment, authored exclusion and caller focus",
    wrappedTabOrder: true,
    callerFocusRestored: true,
    status: "passed",
  });
  mode = "stale";
  await trigger.click();
  await dialog
    .getByRole("button", {
      name: "Use Switzerland as starting point · World / Other / CH [world-other / other-ch]",
    })
    .click();
  await dialog.getByRole("button", { name: "Base descendants" }).press("Enter");
  await dialog
    .getByRole("alert")
    .filter({ hasText: "Refresh the application and reopen the picker" })
    .waitFor();
  assert.equal(
    await dialog
      .getByRole("region", { name: "Available Entity members" })
      .count(),
    0,
  );
  assert.equal(
    await dialog.getByRole("button", { name: "Apply selection" }).isDisabled(),
    true,
  );
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await trigger.evaluate((element) => element === document.activeElement),
    true,
  );
  assert.equal((await page.evaluate(() => window.fixture.applied)).length, 1);
  report.cases.push({
    name: "A stale access context hides earlier placements, disables Apply and retains keyboard cancellation",
    status: "passed",
  });
  mode = "normal";
  const keyboardWidths = [];
  const backgroundTrigger = page.locator("main > button");
  const client = await page.context().newCDPSession(page);
  try {
    for (const width of [650, 651, 684, 950, 951]) {
      await page.setViewportSize({ width, height: 900 });
      await trigger.focus();
      await page.keyboard.press("Enter");
      const sources = dialog.getByRole("navigation", {
        name: "Member sources",
      });
      const hierarchy = sources.getByRole("button", {
        name: "Hierarchy",
        exact: true,
      });
      const lists = sources.getByRole("button", { name: "Member lists" });
      const search = sources.getByRole("button", {
        name: "Search",
        exact: true,
      });
      await hierarchy.waitFor();
      assert.equal(
        await close.evaluate((element) => element === document.activeElement),
        true,
      );
      assert.equal(
        await backgroundTrigger.evaluate((element) => {
          element.focus();
          return element === document.activeElement;
        }),
        false,
        `Background focus must stay unavailable at ${width}px`,
      );
      const { nodes } = await client.send("Accessibility.getFullAXTree");
      assert.equal(
        nodes.some(
          (node) => !node.ignored && node.name?.value === "Choose entities",
        ),
        false,
        `Background trigger must stay outside the accessibility tree at ${width}px`,
      );
      for (const [control, name] of [
        [hierarchy, "Hierarchy"],
        [lists, "Member lists"],
        [search, "Search"],
      ]) {
        await page.keyboard.press("Tab");
        assert.deepEqual(
          await control.evaluate((element) => {
            const rect = element.getBoundingClientRect();
            const atCenter = document.elementFromPoint(
              rect.x + rect.width / 2,
              rect.y + rect.height / 2,
            );
            return {
              label: element.innerText,
              focused:
                element === document.activeElement &&
                element.matches(":focus-visible"),
              visible:
                rect.width > 0 && rect.height > 0 && element.contains(atCenter),
            };
          }),
          { label: name, focused: true, visible: true },
        );
      }
      await page.keyboard.press("Enter");
      const query = dialog.getByRole("textbox", { name: "Find a member" });
      await query.waitFor();
      assert.equal(
        await query.evaluate((element) => element === document.activeElement),
        true,
      );
      await page.keyboard.press("Shift+Tab");
      await page.keyboard.press("Shift+Tab");
      assert.equal(
        await lists.evaluate((element) => element === document.activeElement),
        true,
      );
      await page.keyboard.press("Space");
      const saved = dialog.getByRole("button", { name: /European operations/ });
      await saved.waitFor();
      await page.keyboard.press("Tab");
      await page.keyboard.press("Tab");
      assert.equal(
        await saved.evaluate((element) => element === document.activeElement),
        true,
      );
      await page.keyboard.press("Enter");
      await dialog
        .getByRole("button", { name: "Use European operations dynamically" })
        .waitFor();
      await page.keyboard.press("Escape");
      await dialog.waitFor({ state: "detached" });
      assert.equal(
        await trigger.evaluate((element) => element === document.activeElement),
        true,
      );
      assert.equal(
        (await page.evaluate(() => window.fixture.applied)).length,
        1,
      );
      keyboardWidths.push(width);
    }
  } finally {
    await client.detach();
  }
  report.cases.push({
    name: "Keyboard source navigation, saved list inspection, modal isolation and focus return",
    widths: keyboardWidths,
    status: "passed",
  });
  await trigger.press("Enter");
  await dialog.waitFor();
  await dialog.evaluate((element) => element.requestClose());
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await trigger.evaluate((element) => element === document.activeElement),
    true,
  );
  assert.equal((await page.evaluate(() => window.fixture.applied)).length, 1);
  report.cases.push({
    name: "The browser close request cancels without applying and restores focus",
    status: "passed",
  });
  mode = "saved";
  for (const [width, result] of [
    [1280, "available"],
    [650, "unavailable"],
    [650, "retry"],
  ]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(url + "?saved");
    await page.evaluate(() => {
      window.fixture.prematureConclusions = [];
      new MutationObserver(() => {
        const text = document.querySelector("dialog")?.textContent || "";
        if (
          /no longer active|unavailable in the current context|unavailable in the current catalogue|context unavailable/i.test(
            text,
          )
        )
          window.fixture.prematureConclusions.push(text);
      }).observe(document.body, {
        childList: true,
        characterData: true,
        subtree: true,
      });
    });
    let lookupRead = new Promise((resolve) => (lookupStarted = resolve));
    await trigger.press("Enter");
    const apply = dialog.getByRole("button", { name: "Apply selection" });
    await dialog.getByText("Checking this member…", { exact: true }).waitFor();
    assert.equal(await apply.isDisabled(), true);
    assert.deepEqual(
      await page.evaluate(() => window.fixture.prematureConclusions),
      [],
    );
    await lookupRead;
    if (result === "unavailable") {
      await reply(lookup, "METADATA_SELECTION_SCOPE_UNAVAILABLE", 403);
      lookup = undefined;
      await dialog
        .getByText(
          "Some selected members are unavailable in the current context.",
          { exact: true },
        )
        .waitFor();
      assert.equal(await apply.isDisabled(), true);
      await page.keyboard.press("Escape");
      assert.equal(await page.evaluate(() => window.fixture.applied.length), 0);
    } else {
      if (result === "retry") {
        await reply(lookup, "GATEWAY_UNAVAILABLE", 503);
        lookup = undefined;
        await dialog
          .getByText("The selected members could not be confirmed.", {
            exact: true,
          })
          .waitFor();
        assert.equal(await apply.isDisabled(), true);
        lookupRead = new Promise((resolve) => (lookupStarted = resolve));
        await dialog
          .getByRole("button", { name: "Retry member check" })
          .press("Enter");
        await lookupRead;
        await dialog
          .getByText("Checking this member…", { exact: true })
          .waitFor();
      }
      assert.ok(lookup);
      await reply(lookup, {
        dimensionId: "Entity",
        metadataRevision: 7,
        selectionContextToken: "a".repeat(64),
        hasMore: false,
        nextCursor: null,
        rows: [
          {
            memberId: "CH",
            name: "Switzerland",
            status: "Active",
            shortDescription: "Fixture member",
          },
        ],
      });
      lookup = undefined;
      await dialog.getByText("Switzerland", { exact: true }).waitFor();
      assert.deepEqual(
        await page.evaluate(() => window.fixture.prematureConclusions),
        [],
      );
      assert.equal(await apply.isEnabled(), true);
      await apply.press("Enter");
      assert.deepEqual(
        await page.evaluate(() =>
          window.fixture.applied.map(({ include }) => include),
        ),
        [{ kind: "members", memberIds: ["CH"] }],
      );
    }
    await dialog.waitFor({ state: "detached" });
    report.cases.push({
      name: "An existing member beyond the first page waits for exact confirmation",
      result,
      width,
      status: "passed",
    });
  }
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(report.unexpectedApi, []);
  assert.equal(
    report.apiFunctions.every((fn) => Object.hasOwn(catalog.functions, fn)),
    true,
  );
  report.sourceAfter = await captureSources();
  assert.deepEqual(report.sourceAfter, report.sourceBefore);
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.failure = error.message;
  report.body = await page
    ?.locator("body")
    .innerText()
    .catch(() => "unavailable");
  console.error(JSON.stringify(report, null, 2));
  throw error;
} finally {
  await lookup?.abort().catch(() => {});
  await held?.abort().catch(() => {});
  await browser?.close();
  await server?.close();
  const currentCache = await stat(cacheDir);
  assert.equal(currentCache.dev, cacheIdentity.dev);
  assert.equal(currentCache.ino, cacheIdentity.ino);
  assert.equal(currentCache.uid, cacheIdentity.uid);
  await rm(cacheDir, { recursive: true });
  await assert.rejects(stat(cacheDir), { code: "ENOENT" });
  report.cleanup = {
    browserClosed: true,
    serverClosed: true,
    ownedCacheRemoved: true,
  };
}
if (process.argv[2])
  await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n", {
    flag: "wx",
  });
console.log(JSON.stringify(report, null, 2));
