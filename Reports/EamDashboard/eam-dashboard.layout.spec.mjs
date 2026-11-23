import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const dashboardSourceDir = fileURLToPath(new URL(".", import.meta.url));
const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
let fixtureRoot;
let dashboardUrl;

// The row count has to exceed the table's own max-height so the sticky-header assertion
// below actually scrolls vertically; it stays under the dashboard's default page size.
const fixtureObjects = Array.from({ length: 40 }, (_, index) => ({
    objectId: `00000000-0000-0000-0000-${String(index + 1).padStart(12, "0")}`,
    objectTenantId: "00000000-0000-0000-0000-000000000000",
    objectType: "user",
    objectSubType: "Member",
    objectDisplayName: `Test identity ${index + 1}`,
    objectUserPrincipalName: `test.identity.${index + 1}@contoso.com`,
    objectAdminTierLevel: "1",
    objectAdminTierLevelName: "ManagementPlane",
    syncSource: "Cloud-Only",
    restrictedManagement: "Not available",
    restrictedManagementByAadRole: false,
    restrictedManagementByRAG: false,
    restrictedManagementByRMAU: false,
    assignedAdministrativeUnits: [],
    associatedWorkAccount: [],
    privilegedType: "Local Identities",
    outsideOfHomeTenant: false,
    roleSystem: "EntraID",
    classification: [
        {
            adminTierLevel: "1",
            adminTierLevelName: "ManagementPlane",
            service: "Identity"
        }
    ],
    controlPlaneReasoning: [],
    roleAssignments: []
}));

const fixtureData = {
    tenantName: "Contoso test tenant",
    generatedAt: "2026-01-01T00:00:00Z",
    changeSetId: "browser-test-fixture",
    notifications: [],
    linkedIdentityDisplayNames: {},
    objects: fixtureObjects
};

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-eam-dashboard-browser-"));
    const reportsFixtureDir = join(fixtureRoot, "Reports");
    const dashboardFixtureDir = join(reportsFixtureDir, "EamDashboard");

    await mkdir(reportsFixtureDir, { recursive: true });
    await cp(dashboardSourceDir, dashboardFixtureDir, {
        recursive: true,
        filter: (source) => {
            const sourceRelativePath = relative(dashboardSourceDir, source);
            if (!sourceRelativePath) return true;
            const firstSegment = sourceRelativePath.split(sep)[0];
            return firstSegment !== "data" &&
                !sourceRelativePath.endsWith(".spec.mjs") &&
                sourceRelativePath !== ".DS_Store";
        }
    });
    await cp(join(reportsSourceDir, "shared"), join(reportsFixtureDir, "shared"), { recursive: true });

    const dataDir = join(dashboardFixtureDir, "data");
    await mkdir(dataDir, { recursive: true });
    await writeFile(
        join(dataDir, "eam-dashboard-data.js"),
        `window.ENTRAOPS_EAM_DATA = ${JSON.stringify(fixtureData)};\n`,
        "utf8"
    );

    dashboardUrl = pathToFileURL(join(dashboardFixtureDir, "index.html")).href;
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

for (const viewport of [
    { name: "desktop", width: 1472, height: 768 },
    { name: "mobile", width: 390, height: 844 }
]) {
    test(`${viewport.name} keeps the dashboard shell and wide tables inside the viewport`, async ({ page }) => {
        await page.setViewportSize(viewport);
        await page.goto(dashboardUrl);
        await expect(page.locator("#assetTable tbody tr").first()).toBeVisible();

        const layout = await page.evaluate(() => {
            const main = document.querySelector(".main").getBoundingClientRect();
            const nav = document.querySelector(".nav").getBoundingClientRect();
            const tableScroll = document.querySelector("#secAssets .eam-scroll");
            const scrollBounds = tableScroll.getBoundingClientRect();

            return {
                documentOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                mainLeft: main.left,
                navRight: nav.right,
                scrollLeft: scrollBounds.left,
                scrollRight: scrollBounds.right,
                scrollClientWidth: tableScroll.clientWidth,
                scrollWidth: tableScroll.scrollWidth
            };
        });

        expect(layout.documentOverflow).toBeLessThanOrEqual(1);
        expect(layout.mainLeft).toBeGreaterThanOrEqual(layout.navRight - 1);
        expect(layout.scrollLeft).toBeGreaterThanOrEqual(layout.mainLeft - 1);
        expect(layout.scrollRight).toBeLessThanOrEqual(viewport.width + 1);
        expect(layout.scrollWidth).toBeGreaterThan(layout.scrollClientWidth);

        await page.locator("html").evaluate((element) => {
            element.dataset.theme = "dark";
        });
        await page.locator("#assetTable tbody tr.asset-row").first().click();
        const selectedRowColors = await page.locator("#assetTable tbody tr.sel-row").evaluate((row) => ({
            row: getComputedStyle(row).backgroundColor,
            actionCell: getComputedStyle(row.cells[12]).backgroundColor
        }));
        expect(selectedRowColors.actionCell).toBe(selectedRowColors.row);

        const stickyHeaderDelta = await page.locator("#secAssets .eam-scroll").evaluate((tableScroll) => {
            tableScroll.scrollLeft = 500;
            tableScroll.scrollTop = 300;
            const scrollTop = tableScroll.getBoundingClientRect().top;
            const headerTop = tableScroll.querySelector("thead th").getBoundingClientRect().top;
            return Math.abs(headerTop - scrollTop);
        });

        expect(stickyHeaderDelta).toBeLessThanOrEqual(1);
    });
}

test("asset deep link flashes a known asset and shows a notice for an unknown one", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${dashboardUrl}#asset=${fixtureObjects[2].objectId}`);
    await expect(page.locator(`#assetTable tbody tr[data-id="${fixtureObjects[2].objectId}"]`)).toHaveClass(/eo-flash/);
    await expect(page.locator("#eoDeepLinkNotice")).toHaveCount(0);

    const unknownId = "99999999-9999-9999-9999-999999999999";
    await page.evaluate((id) => { location.hash = "#asset=" + id; }, unknownId);
    await expect(page.locator("#eoDeepLinkNotice")).toBeVisible();
    await expect(page.locator("#eoDeepLinkNotice")).toContainText(`Privileged asset ${unknownId} was not found in the Privileged EAM data.`);
    expect(pageErrors).toEqual([]);
});

test("hand-over parameters keep several identity tiers and the search", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    // Several tiers (the Privilege History tier level filter) are kept, not dropped.
    await page.goto(`${dashboardUrl}?rs=*&objectTier=ControlPlane,ManagementPlane`);
    await expect(page.locator("#assetTable tbody tr[data-id]")).toHaveCount(40);
    await expect(page.locator(".chip.brand", { hasText: "Identity classification" })).toContainText("Control Plane, Management Plane");
    await page.goto(`${dashboardUrl}?rs=*&objectTier=ControlPlane`);
    await expect(page.locator("#assetTable tbody tr[data-id]")).toHaveCount(0);
    // &q= fills the search.
    await page.goto(`${dashboardUrl}?rs=*&objectTier=*&q=${encodeURIComponent("Test identity 12")}`);
    await expect(page.locator("#fltDisplayName")).toHaveValue("Test identity 12");
    await expect(page.locator("#assetTable tbody tr[data-id]")).toHaveCount(1);
    expect(pageErrors).toEqual([]);
});

test("asset deep link clears the filters that hide the asset", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${dashboardUrl}?rs=*&objectTier=ControlPlane`);
    await expect(page.locator("#assetTable tbody tr[data-id]")).toHaveCount(0);
    // An upper-case ID matches too.
    await page.evaluate((id) => { location.hash = "#asset=" + id; }, fixtureObjects[5].objectId.toUpperCase());
    await expect(page.locator(`#assetTable tbody tr[data-id="${fixtureObjects[5].objectId}"]`)).toHaveClass(/eo-flash/);
    await expect(page.locator("#eoDeepLinkNotice")).toHaveCount(0);
    await expect(page.locator(".chip.brand", { hasText: "Identity classification" })).toHaveCount(0);
    expect(pageErrors).toEqual([]);
});

async function setActionFixture(page, system, scopeNames = ["first", "second"]) {
    const action = system === "Azure" ? "Microsoft.Authorization/roleAssignments/write" : "microsoft.directory/users/password/update";
    const scopes = scopeNames.map((name) => `${system === "Azure" ? "/subscriptions/" : "/administrativeUnits/"}${name}`);
    const classification = {
        adminTierLevelName: "ManagementPlane", service: "Identity", taggedBy: "JSONwithAction",
        matchedActions: [action]
    };
    const assignments = scopes.map((scope, index) => ({
        roleAssignmentId: `assignment-${index}`, roleAssignmentInstanceId: `instance-${index}`,
        roleDefinitionName: "Scoped Operator", roleDefinitionId: "test-role",
        roleAssignmentScopeName: "Shared display name", roleAssignmentScopeId: scope,
        roleAssignmentType: "Direct", pimAssignmentType: "Permanent",
        classification: [classification]
    }));
    await page.addInitScript((data) => {
        Object.defineProperty(window, "ENTRAOPS_EAM_DATA", { get: () => data, set() { } });
    }, { ...fixtureData, objects: [{ ...fixtureObjects[0], roleSystem: system, roleAssignments: assignments }] });
    return { action, scopes, assignments };
}

for (const system of ["Azure", "EntraID"]) {
    test(`bookmarked ${system} actions keep scope context and require explicit overwrite inputs across apps`, async ({ page }) => {
        const pageErrors = [];
        page.on("pageerror", (error) => pageErrors.push(error.message));
        const { action, scopes } = await setActionFixture(page, system);
        // Route both apps on one origin to exercise the real shared localStorage, without tenant bundles.
        await page.route("http://entraops.test/Reports/**", async (route) => {
            const path = new URL(route.request().url()).pathname.slice("/Reports/".length);
            if (path.startsWith("ClassificationExplorer/data/")) {
                await route.fulfill({ contentType: "text/javascript", body: "window.EOCE_DATA = {}; window.EOCE_TENANTS = [];" });
                return;
            }
            const root = path.startsWith("EamDashboard/") ? join(fixtureRoot, "Reports") : reportsSourceDir;
            const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".svg": "image/svg+xml" };
            await route.fulfill({ contentType: types[extname(path)] || "application/octet-stream", body: await readFile(join(root, path)) });
        });
        const origin = "http://entraops.test/Reports";
        const dashboard = `${origin}/EamDashboard/index.html`;
        await page.goto(`${dashboard}?rs=*`);
        await page.locator("#classificationTable [data-det]").first().click();
        const stars = page.locator("#drawerBody [data-review-action]");
        await expect(stars).toHaveCount(2);
        await stars.first().click();
        const saved = await page.evaluate(() => window.EOReview.all());
        expect(saved).toEqual([expect.objectContaining({
            kind: "Role action", system, name: action, scope: scopes[0],
            tier: "ManagementPlane", app: "EamDashboard"
        })]);
        await stars.nth(1).click();
        expect(await page.evaluate(() => window.EOReview.count())).toBe(2);
        await stars.nth(1).click();
        expect(await page.evaluate(() => window.EOReview.count())).toBe(1);

        await page.goto(dashboard + saved[0].hash);
        await expect(page.locator("#drawer")).toHaveClass(/open/);
        await expect(page.locator("#drawerBody [data-review-action]").first()).toBeVisible();
        await expect(page.locator("#drawerBody [data-review-action]").first()).toHaveAttribute("aria-pressed", "true");
        await expect(page.locator("#drawerBody [data-review-action]").first()).toBeFocused();

        await page.goto(`${origin}/ClassificationExplorer/index.html#customize/roleaction`);
        await page.locator("#custAdd").click();
        await expect(page.locator("#cfReview")).toContainText(scopes[0]);
        await page.locator("#cfReview").getByRole("button", { name: "Add action", exact: true }).click();
        await expect(page.locator("#cfSys")).toHaveValue(system);
        await expect(page.locator("#cfActionChips")).toContainText(action);
        await expect(page.locator("#cfScopes")).toHaveValue("");
        await page.locator("#cfApply").click();
        await expect(page.locator("#cfError")).toContainText("Enter the overwrite scope explicitly");
        await expect(page.locator("#cfError")).toContainText("Select a tier level");
        await expect(page.locator("#cfError")).toContainText("A Justification is mandatory");
        await page.locator("#cfScopes").fill(scopes[0]);
        await page.locator("#cfTier").selectOption("ControlPlane");
        await page.locator("#cfJust").fill("Explicit scope review");
        await page.locator("#cfApply").click();
        const downloadPromise = page.waitForEvent("download");
        await page.locator("#custExport").click();
        const download = await downloadPromise;
        expect(JSON.parse(await readFile(await download.path(), "utf8"))).toEqual([{
            RbacSystem: system, RoleDefinitionActions: [action], RoleAssignmentScopeName: [scopes[0]],
            EAMTierLevelName: "ControlPlane", EAMTierLevelTagValue: "0", Justification: "Explicit scope review"
        }]);
        expect(pageErrors).toEqual([]);
    });
}

test("action stars stay synchronized across assignment and asset classification evidence", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await setActionFixture(page, "Azure");
    await page.goto(`${dashboardUrl}?rs=*`);
    await page.locator("#assignmentTable [data-cls]").first().click();
    await page.locator("#drawerBody .decision-evidence summary").click();
    await page.locator("#drawerBody [data-review-action]").click();
    await page.locator("#drawerClose").click();
    await page.locator("#assetTable [data-cls]").first().click();
    await page.locator("#drawerBody .decision-evidence summary").first().click();
    await expect(page.locator("#drawerBody [data-review-action]").first()).toHaveAttribute("aria-pressed", "true");
    await page.locator("#drawerBody [data-review-action]").first().click();
    expect(await page.evaluate(() => window.EOReview.count())).toBe(0);
    await page.reload();
    await page.locator("#assignmentTable [data-cls]").first().click();
    await page.locator("#drawerBody .decision-evidence summary").click();
    await expect(page.locator("#drawerBody [data-review-action]")).toHaveAttribute("aria-pressed", "false");
    expect(pageErrors).toEqual([]);
});

test("classification row evidence limits the scopes listed per action and keeps starred ones", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    const { scopes } = await setActionFixture(page, "Azure", ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]);
    await page.goto(`${dashboardUrl}?rs=*`);
    await page.locator("#classificationTable [data-det]").first().click();
    await expect(page.locator("#drawerBody [data-review-action]")).toHaveCount(5);
    await expect(page.locator("#drawerBody [data-review-action-more]")).toContainText("3 more scope(s)");

    // A scope beyond the limit is starred in the reasoning of its assignment and then listed first.
    await page.locator("#drawerClose").click();
    await page.evaluate(() => { location.hash = "#assignment=instance-7"; });
    await page.locator("#assignmentTable tr.eo-flash [data-cls]").click();
    await page.locator("#drawerBody .decision-evidence summary").click();
    await page.locator("#drawerBody [data-review-action]").click();
    await page.locator("#drawerClose").click();
    await page.locator("#classificationTable [data-det]").first().click();
    await expect(page.locator("#drawerBody [data-review-action]")).toHaveCount(5);
    await expect(page.locator("#drawerBody li", { has: page.locator("[data-review-action]") }).first()).toContainText(scopes[7]);
    await expect(page.locator("#drawerBody [data-review-action]").first()).toHaveAttribute("aria-pressed", "true");
    expect(pageErrors).toEqual([]);
});
