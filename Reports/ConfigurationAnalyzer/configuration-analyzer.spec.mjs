import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const appSourceDir = fileURLToPath(new URL(".", import.meta.url));
const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
let fixtureRoot;
let appUrl;
let noEamAppUrl;

const adminId = "aaaaaaaa-0000-0000-0000-000000000001";
const helpdeskId = "aaaaaaaa-0000-0000-0000-000000000002";
const unknownId = "99999999-9999-9999-9999-999999999999";
const blockLegacyId = "c0000000-0000-0000-0000-000000000001";

const CA = "microsoft.entra.conditionalaccesspolicy";
const GROUP = "microsoft.entra.group";
const LOCATION = "microsoft.entra.namedlocationpolicy";
const INTUNE = "microsoft.intune.deviceconfigurationpolicywindows10";

// Two snapshots of contoso: the second one adds two resources, modifies two and removes one.
const configurationData = {
    tenantName: "contoso.onmicrosoft.com",
    generatedAt: "2026-01-09T00:00:00Z",
    snapshots: [
        {
            commitSha: "1111111111111111111111111111111111111111", commitDate: "2026-01-01T08:00:00Z", subject: "Snapshot 1", hasDetail: true,
            resources: [
                { p: `${CA}/Policies/BlockLegacy.json`, h: "ca1" },
                { p: `${CA}/Policies/RequireMfa.json`, h: "ca2" },
                { p: `${GROUP}/Groups/Tier0Admins.json`, h: "g1" },
                { p: `${GROUP}/Groups/Helpdesk.json`, h: "g2" },
                { p: `${INTUNE}/Policies/Baseline.json`, h: "i1" }
            ]
        },
        {
            commitSha: "2222222222222222222222222222222222222222", commitDate: "2026-01-08T08:00:00Z", subject: "Snapshot 2", hasDetail: true,
            resources: [
                { p: `${CA}/Policies/BlockLegacy.json`, h: "ca1b" },
                { p: `${CA}/Policies/RequireMfa.json`, h: "ca2" },
                { p: `${CA}/Policies/RequireCompliant.json`, h: "ca3" },
                { p: `${GROUP}/Groups/Tier0Admins.json`, h: "g1" },
                { p: `${GROUP}/Groups/Helpdesk.json`, h: "g2b" },
                { p: `${LOCATION}/Locations/Office.json`, h: "nl1" }
            ]
        }
    ],
    blobs: {
        ca1: { properties: { Id: blockLegacyId, DisplayName: "BlockLegacy", State: "disabled", IncludeUsers: [adminId] } },
        ca1b: { properties: { Id: blockLegacyId, DisplayName: "BlockLegacy", State: "enabled", IncludeUsers: [adminId] } },
        ca2: { properties: { Id: "c0000000-0000-0000-0000-000000000002", DisplayName: "RequireMfa", State: "enabled", IncludeUsers: ["All"] } },
        ca3: { properties: { Id: "c0000000-0000-0000-0000-000000000003", DisplayName: "RequireCompliant", State: "enabled", IncludeUsers: [helpdeskId] } },
        g1: { properties: { Id: "60000000-0000-0000-0000-000000000001", DisplayName: "Tier0Admins", Members: [adminId] } },
        g2: { properties: { Id: "60000000-0000-0000-0000-000000000002", DisplayName: "Helpdesk", Members: [helpdeskId] } },
        g2b: { properties: { Id: "60000000-0000-0000-0000-000000000002", DisplayName: "Helpdesk", Members: [helpdeskId, unknownId] } },
        i1: { properties: { Id: "70000000-0000-0000-0000-000000000001", DisplayName: "Baseline" } },
        nl1: { properties: { Id: "80000000-0000-0000-0000-000000000001", DisplayName: "Office" } }
    }
};

const eamData = {
    objects: [
        { objectId: adminId, objectType: "user", objectDisplayName: "Admin A", objectUserPrincipalName: "admin@contoso.com", objectAdminTierLevelName: "ControlPlane", classification: [{ service: "Identity", adminTierLevelName: "ControlPlane" }], roleAssignments: [] },
        { objectId: helpdeskId, objectType: "user", objectDisplayName: "Helpdesk B", objectUserPrincipalName: "helpdesk@contoso.com", objectAdminTierLevelName: "ManagementPlane", classification: [{ service: "Helpdesk", adminTierLevelName: "ManagementPlane" }], roleAssignments: [] }
    ]
};

async function writeAppFixture(reportsRoot, withEamData, data = configurationData) {
    const appFixtureDir = join(reportsRoot, "ConfigurationAnalyzer");
    await mkdir(reportsRoot, { recursive: true });
    await cp(join(reportsSourceDir, "shared"), join(reportsRoot, "shared"), { recursive: true });
    await cp(appSourceDir, appFixtureDir, {
        recursive: true,
        filter: (source) => {
            const sourceRelativePath = relative(appSourceDir, source);
            if (!sourceRelativePath) return true;
            return sourceRelativePath.split(sep)[0] !== "data" && !sourceRelativePath.endsWith(".spec.mjs") && sourceRelativePath !== ".DS_Store";
        }
    });
    await mkdir(join(appFixtureDir, "data"), { recursive: true });
    await writeFile(join(appFixtureDir, "data", "configuration-analyzer-data.js"), `window.ENTRAOPS_CONFIGANALYZER_DATA = ${JSON.stringify(data)};\n`, "utf8");
    if (withEamData) {
        await mkdir(join(reportsRoot, "EamDashboard", "data"), { recursive: true });
        await writeFile(join(reportsRoot, "EamDashboard", "data", "eam-dashboard-data.js"), `window.ENTRAOPS_EAM_DATA = ${JSON.stringify(eamData)};\n`, "utf8");
    }
    return pathToFileURL(join(appFixtureDir, "index.html")).href;
}

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-configuration-analyzer-browser-"));
    appUrl = await writeAppFixture(join(fixtureRoot, "Reports"), true);
    noEamAppUrl = await writeAppFixture(join(fixtureRoot, "ReportsNoEam"), false);
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

async function openApp(page, suffix = "", url = appUrl) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(url + suffix);
    await page.evaluate(() => {
        window.__exported = null;
        window.EntraOpsReportUtils.exportRows = (name, rows) => { window.__exported = { name, rows }; };
    });
    return pageErrors;
}

function pillCount(container, value) {
    return container.locator(`[data-value="${value}"] .eo-pill-count`);
}

test("snapshot changes filter by change and access tier pills with live counts", async ({ page }) => {
    const pageErrors = await openApp(page);
    const changes = page.locator("#changesBody");
    const statusPills = changes.locator('[data-facet="statusFilter"]');
    const tierPills = changes.locator('.eo-pills[aria-label="Access tier"]');
    const rows = changes.locator("tbody tr[data-row]");

    await expect(rows).toHaveCount(5);
    await expect(statusPills).toHaveCount(4);
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""] .eo-pill-count')).toHaveText("5");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="added"] .eo-pill-count')).toHaveText("2");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="modified"] .eo-pill-count')).toHaveText("2");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="removed"] .eo-pill-count')).toHaveText("1");
    await expect(pillCount(tierPills, "")).toHaveText("5");
    await expect(pillCount(tierPills, "__privileged")).toHaveText("3");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("1");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("2");
    await expect(pillCount(tierPills, "UserAccess")).toHaveText("1");
    await expect(changes.locator('[data-flt="clear"]')).toBeDisabled();

    // A tier pill filters the rows and updates the counts of the change pills.
    await tierPills.locator('[data-value="ControlPlane"]').click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("BlockLegacy");
    await expect(tierPills.locator('[data-value="ControlPlane"]')).toHaveAttribute("aria-pressed", "true");
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""] .eo-pill-count')).toHaveText("1");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="modified"] .eo-pill-count')).toHaveText("1");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="added"]')).toBeDisabled();

    // The export holds the filtered rows only.
    await page.click("#changesExport");
    expect(await page.evaluate(() => window.__exported.rows.map((row) => row.name))).toEqual(["BlockLegacy"]);

    // A second click on the active pill shows all rows again.
    await tierPills.locator('[data-value="ControlPlane"]').click();
    await expect(rows).toHaveCount(5);
    await expect(tierPills.locator('[data-value=""]')).toHaveAttribute("aria-pressed", "true");

    await changes.locator('[data-facet="statusFilter"][data-value="added"]').click();
    await expect(rows).toHaveCount(2);
    await expect(pillCount(tierPills, "")).toHaveText("2");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("1");

    // The change pills are multi-select: added + modified, then "All" clears the selection.
    await changes.locator('[data-facet="statusFilter"][data-value="modified"]').click();
    await expect(rows).toHaveCount(4);
    await expect(changes.locator('[data-facet="statusFilter"][data-value="added"]')).toHaveAttribute("aria-pressed", "true");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="modified"]')).toHaveAttribute("aria-pressed", "true");
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""]')).toHaveAttribute("aria-pressed", "false");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="modified"]')).toBeFocused();
    await expect(pillCount(tierPills, "")).toHaveText("4");
    await expect(pillCount(tierPills, "__privileged")).toHaveText("3");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("1");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("2");
    await page.click("#changesExport");
    expect(await page.evaluate(() => window.__exported.rows.map((row) => row.status).sort())).toEqual(["added", "added", "modified", "modified"]);
    await changes.locator('[data-facet="statusFilter"][data-value="added"]').click();
    await expect(rows).toHaveCount(2);
    await expect(changes.locator('[data-facet="statusFilter"][data-value="modified"]')).toHaveAttribute("aria-pressed", "true");
    await changes.locator('[data-facet="statusFilter"][data-value="added"]').click();
    await changes.locator('[data-facet="statusFilter"][data-value=""]').click();
    await expect(rows).toHaveCount(5);
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""]')).toHaveAttribute("aria-pressed", "true");
    await expect(changes.locator('[data-facet="statusFilter"][aria-pressed="true"]')).toHaveCount(1);

    // The category dropdown narrows the rows and the counts.
    await changes.locator('select[data-flt="category"]').selectOption("Groups");
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("Helpdesk");
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""] .eo-pill-count')).toHaveText("1");
    await expect(changes.locator('[data-facet="statusFilter"][data-value="modified"] .eo-pill-count')).toHaveText("1");

    // Clicking a status value in the table filters by it.
    await changes.locator('select[data-flt="category"]').selectOption("");
    await changes.locator('[data-facet="statusFilter"][data-value="added"]').click();
    await changes.locator('[data-facet="statusFilter"][data-value="removed"]').click();
    await expect(rows).toHaveCount(3);
    await changes.locator('[data-status-flt="removed"]').click();
    await expect(rows).toHaveCount(1);
    await expect(changes.locator('[data-facet="statusFilter"][data-value="removed"]')).toHaveAttribute("aria-pressed", "true");
    await expect(changes.locator('[data-facet="statusFilter"][aria-pressed="true"]')).toHaveCount(1);

    await changes.locator('select[data-flt="classification"]').selectOption("Helpdesk");
    await expect(changes.locator(".muted", { hasText: "No changes match the current filters." })).toBeVisible();
    await changes.locator('[data-flt="clear"]').click();
    await expect(rows).toHaveCount(5);
    await expect(changes.locator('[data-flt="clear"]')).toBeDisabled();
    await expect(changes.locator('select[data-flt="classification"]')).toHaveValue("");

    // The resource type dropdown of the timeline filters the change list.
    await page.selectOption("#fltResourceType", GROUP);
    await expect(rows).toHaveCount(1);
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""] .eo-pill-count')).toHaveText("1");
    await page.selectOption("#timelineView", "all");
    await expect(page.locator("#timelineChart svg")).toHaveCount(1);

    // Compare two snapshots renders the same filters for its own list.
    await page.selectOption("#fltResourceType", "");
    await page.click("#cmpRun");
    await expect(page.locator("#cmpResult tbody tr[data-row]")).toHaveCount(5);
    await expect(page.locator('#cmpResult [data-facet="statusFilter"][data-value="added"] .eo-pill-count')).toHaveText("2");
    expect(pageErrors).toEqual([]);
});

test("snapshot resources filter by state and access tier pills, dropdowns and search", async ({ page }) => {
    const pageErrors = await openApp(page, "?view=resources");
    const modePills = page.locator("#asrChangeModePills");
    const tierPills = page.locator("#asrTierPills");
    const listHead = page.locator(".asr-list-head > span").first();

    await expect(listHead).toHaveText("6 of 6 resources in 3 families");
    await expect(pillCount(modePills, "")).toHaveText("6");
    await expect(pillCount(modePills, "changed")).toHaveText("4");
    await expect(pillCount(modePills, "added")).toHaveText("2");
    await expect(pillCount(modePills, "modified")).toHaveText("2");
    await expect(pillCount(modePills, "removed")).toHaveText("1");
    await expect(pillCount(tierPills, "")).toHaveText("6");
    await expect(pillCount(tierPills, "__privileged")).toHaveText("4");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("2");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("2");
    await expect(pillCount(tierPills, "UserAccess")).toHaveText("1");

    await modePills.locator('[data-value="added"]').click();
    await expect(listHead).toHaveText("2 of 6 resources in 2 families");
    await expect(pillCount(tierPills, "")).toHaveText("2");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("1");
    await expect(tierPills.locator('[data-value="ControlPlane"]')).toBeDisabled();
    await page.click("#asrExport");
    expect(await page.evaluate(() => window.__exported.rows.map((row) => row.name).sort())).toEqual(["Office", "RequireCompliant"]);
    await modePills.locator('[data-value="added"]').click();
    await expect(listHead).toHaveText("6 of 6 resources in 3 families");

    // Removed resources are listed from the baseline snapshot.
    await modePills.locator('[data-value="removed"]').click();
    await expect(listHead).toHaveText("1 of 5 resources in 1 families");
    await modePills.locator('[data-value=""]').click();

    await tierPills.locator('[data-value="ControlPlane"]').click();
    await expect(listHead).toHaveText("2 of 6 resources in 2 families");
    await expect(pillCount(modePills, "")).toHaveText("2");
    await expect(pillCount(modePills, "modified")).toHaveText("1");
    await expect(modePills.locator('[data-value="added"]')).toBeDisabled();
    await tierPills.locator('[data-value="ControlPlane"]').click();

    await page.selectOption("#asrType", GROUP);
    await expect(listHead).toHaveText("2 of 6 resources in 1 families");
    await expect(pillCount(modePills, "")).toHaveText("2");
    await page.selectOption("#asrClassification", "Identity");
    await expect(listHead).toHaveText("1 of 6 resources in 1 families");

    await page.click("#asrClearFilters");
    await expect(listHead).toHaveText("6 of 6 resources in 3 families");
    await page.fill("#asrSearch", "helpdesk");
    await expect(listHead).toHaveText("1 of 6 resources in 1 families");
    await expect(pillCount(modePills, "")).toHaveText("1");
    await expect(pillCount(modePills, "modified")).toHaveText("1");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("0");

    await modePills.locator('[data-value="modified"]').click();
    await tierPills.locator('[data-value="UserAccess"]').click();
    await page.click("#asrClearFilters");
    await expect(page.locator("#asrSearch")).toHaveValue("");
    await expect(page.locator("#asrType")).toHaveValue("");
    await expect(modePills.locator('[data-value=""]')).toHaveAttribute("aria-pressed", "true");
    await expect(tierPills.locator('[data-value=""]')).toHaveAttribute("aria-pressed", "true");
    await expect(listHead).toHaveText("6 of 6 resources in 3 families");
    expect(pageErrors).toEqual([]);
});

test("configuration assets filter by access tier pills, search and the include-all option", async ({ page }) => {
    const pageErrors = await openApp(page, "?view=privileged");
    const tierPills = page.locator("#paTierPills");
    const rows = page.locator("#privilegedAssetsBody tbody tr");

    await expect(rows).toHaveCount(2);
    await expect(pillCount(tierPills, "")).toHaveText("2");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("2");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("2");
    await expect(pillCount(tierPills, "UserAccess")).toHaveText("1");

    await tierPills.locator('[data-value="UserAccess"]').click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText(GROUP);
    await page.click("#paExport");
    expect(await page.evaluate(() => window.__exported.rows.map((row) => row.resourceType))).toEqual([GROUP]);
    await tierPills.locator('[data-value="UserAccess"]').click();
    await expect(rows).toHaveCount(2);

    await page.check("#paIncludeAllTypes");
    await expect(rows).toHaveCount(3);
    await expect(pillCount(tierPills, "")).toHaveText("3");
    await page.uncheck("#paIncludeAllTypes");

    await page.fill("#paSearch", "Tier0");
    await expect(rows).toHaveCount(1);
    await expect(pillCount(tierPills, "")).toHaveText("1");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("1");
    await page.fill("#paSearch", "");

    // A tier count in the table selects the type and the tier pill.
    await page.locator('#privilegedAssetsBody [data-pa-detail="ManagementPlane"]').first().click();
    await expect(tierPills.locator('[data-value="ManagementPlane"]')).toHaveAttribute("aria-pressed", "true");
    await expect(rows).toHaveCount(2);
    expect(pageErrors).toEqual([]);
});

test("object deep link opens the resource with cleared filters", async ({ page }) => {
    const pageErrors = await openApp(page, `#object=${blockLegacyId}`);
    await expect(page.locator("#secAllSnapshotResources")).toBeVisible();
    await expect(page.locator(".asr-detail-head strong")).toHaveText("BlockLegacy");
    await expect(page.locator('#asrChangeModePills [data-value=""]')).toHaveAttribute("aria-pressed", "true");
    // The page resolves #object= itself: the shared object inspector must not open an "Object reference" drawer on top.
    await expect(page.locator("#objectInspector.open")).toHaveCount(0);
    await expect(page.locator("#eoDeepLinkNotice")).toHaveCount(0);
    await page.evaluate((id) => { location.hash = "#object=" + encodeURIComponent("microsoft.entra.conditionalaccesspolicy|" + id); }, blockLegacyId);
    await expect(page.locator(".asr-detail-head strong")).toHaveText("BlockLegacy");
    await expect(page.locator("#objectInspector.open")).toHaveCount(0);
    expect(pageErrors).toEqual([]);
});

test("object deep link with a type named like a member of Object.prototype names it a resource", async ({ page }) => {
    const pageErrors = await openApp(page, `#object=${encodeURIComponent("constructor|" + unknownId)}`);
    await expect(page.locator("#eoDeepLinkNotice")).toBeVisible();
    await expect(page.locator("#eoDeepLinkNotice")).toContainText(`Resource ${unknownId} was not found in the loaded snapshots.`);
    await expect(page.locator("#eoDeepLinkNotice")).not.toContainText("function");
    expect(pageErrors).toEqual([]);
});

test("object deep link to an unknown object shows a notice", async ({ page }) => {
    const pageErrors = await openApp(page, `#object=${unknownId}`);
    await expect(page.locator("#eoDeepLinkNotice")).toBeVisible();
    await expect(page.locator("#eoDeepLinkNotice")).toContainText(`Object ${unknownId} was not found in the loaded snapshots.`);
    await expect(page.locator("#objectInspector.open")).toHaveCount(0);
    await page.locator("#eoDeepLinkNotice button").click();
    await expect(page.locator("#eoDeepLinkNotice")).toBeHidden();
    expect(pageErrors).toEqual([]);
});

test("without the EAM Dashboard dataset the access tier pills are replaced by a note", async ({ page }) => {
    const pageErrors = await openApp(page, "", noEamAppUrl);
    const changes = page.locator("#changesBody");
    await expect(changes.locator("tbody tr[data-row]")).toHaveCount(5);
    await expect(changes.locator('[data-facet="tierFilter"]')).toHaveCount(0);
    await expect(changes.locator('select[data-flt="classification"]')).toHaveCount(0);
    await expect(changes.locator(".eo-facet-note")).toContainText("eam-dashboard-data.js");
    await changes.locator('[data-facet="statusFilter"][data-value="removed"]').click();
    await expect(changes.locator("tbody tr[data-row]")).toHaveCount(1);

    await page.goto(noEamAppUrl + "?view=resources");
    await expect(page.locator("#asrTierPills")).toContainText("Privileged-asset filters require the EAM Dashboard dataset.");
    await expect(page.locator("#asrClassificationFilter")).toBeHidden();
    expect(pageErrors).toEqual([]);
});

test("Snapshot changes and Compare keep their own change filters, and each export uses its own", async ({ page }) => {
    const pageErrors = await openApp(page);
    const changes = page.locator("#changesBody");
    await expect(changes.locator("tbody tr[data-row]")).toHaveCount(5);
    await page.click("#cmpRun");
    const compare = page.locator("#cmpResult");
    await compare.locator('[data-facet="statusFilter"][data-value="modified"]').click();
    await expect(compare.locator("tbody tr[data-row]")).toHaveCount(2);
    // The Snapshot changes list is not filtered by the Compare filter.
    await expect(changes.locator("tbody tr[data-row]")).toHaveCount(5);
    await expect(changes.locator('[data-facet="statusFilter"][data-value=""]')).toHaveAttribute("aria-pressed", "true");
    await page.click("#changesExport");
    expect(await page.evaluate(() => window.__exported.rows.length)).toBe(5);
    await page.click("#compareExport");
    expect(await page.evaluate(() => window.__exported.rows.map((row) => row.status))).toEqual(["modified", "modified"]);
    expect(pageErrors).toEqual([]);
});

test("an object deep link without a type opens the PIM role setting, not the role definition of the same ID", async ({ page }) => {
    const roleId = "62e90394-69f5-4237-9190-012177145e10";
    const data = structuredClone(configurationData);
    data.snapshots[1].resources.push(
        { p: "microsoft.entra.roledefinition/Roles/GlobalAdministratorDefinition.json", h: "rd1" },
        { p: "microsoft.entra.rolesetting/Roles/GlobalAdministratorSetting.json", h: "rs1" }
    );
    data.blobs.rd1 = { properties: { Id: roleId, DisplayName: "Global Administrator (definition)" } };
    data.blobs.rs1 = { properties: { Id: roleId, DisplayName: "Global Administrator (setting)" } };
    const url = await writeAppFixture(join(fixtureRoot, "ReportsRoleSetting"), true, data);
    const pageErrors = await openApp(page, `#object=${roleId.toUpperCase()}`, url);
    await expect(page.locator(".asr-detail-head")).toContainText("GlobalAdministratorSetting");
    expect(pageErrors).toEqual([]);
});
