import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const appSourceDir = fileURLToPath(new URL(".", import.meta.url));
const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
let fixtureRoot;
let appUrl;
let csaAppUrl;
let mixedAppUrl;

const userId = "11111111-1111-1111-1111-111111111111";
const servicePrincipalId = "22222222-2222-2222-2222-222222222222";
const groupId = "55555555-5555-5555-5555-555555555555";
const ownerId = "33333333-3333-3333-3333-333333333333";

function summary(byTier, eligible, active) {
    const total = Object.values(byTier).reduce((sum, count) => sum + count, 0);
    const order = ["ControlPlane", "ManagementPlane", "WorkloadPlane", "UserAccess"];
    return {
        total, eligible, active, bySystem: { EntraID: total },
        byTier: { ControlPlane: 0, ManagementPlane: 0, WorkloadPlane: 0, UserAccess: 0, Unclassified: 0, ...byTier },
        highestTierName: order.find((tier) => byTier[tier]) || "Unclassified"
    };
}

function object(overrides) {
    return {
        objectTenantId: "t1", objectSubType: "Member", userPrincipalName: "", tierLevel: "", onPremSynchronized: false,
        restrictedManagementByRAG: false, restrictedManagementByAadRole: false, restrictedManagementByRMAU: false,
        restrictedManagement: "Not applied", identityParent: "", administrativeUnits: [], roleSystems: ["EntraID"],
        owners: [], sponsors: [], ownedObjects: [], ownedDevices: [], associatedWorkAccount: [], associatedPawDevice: [],
        isForeign: false, assignments: [], ...overrides
    };
}

const fixtureData = {
    tenantName: "contoso.onmicrosoft.com",
    generatedAt: "2026-01-01T00:00:00Z",
    homeTenantId: "t1",
    classificationSettings: {
        customSecurityAttributes: {
            enabledFor: { user: false, servicePrincipal: false, application: false },
            userAttributeSet: "privilegedUser", userTierLevelAttribute: "adminTierLevel", userTierNameAttribute: "adminTierLevelName",
            servicePrincipalAttributeSet: "privilegedWorkloadIdentity", servicePrincipalTierLevelAttribute: "adminTierLevel", servicePrincipalTierNameAttribute: "adminTierLevelName"
        },
        alternateObjectTierLevelAttributes: { user: false, servicePrincipal: false, group: false },
        objectClassificationFile: {
            enabled: true, filePath: "./Classification/ObjectClassification.json", error: "",
            entries: [{ objectId: userId, objectType: "user", objectDisplayName: "Admin A", adminTierLevelName: "ControlPlane", justification: "GA" }]
        }
    },
    objects: [
        object({
            objectId: userId, objectType: "user", displayName: "Admin A", userPrincipalName: "a@contoso.com", tierName: "Unclassified",
            onPremSynchronized: true, ownedObjects: [servicePrincipalId], ownedDevices: ["44444444-4444-4444-4444-444444444444"],
            administrativeUnits: [{ id: "au1", displayName: "Tier0-AU" }],
            assignments: [{ id: "EO_RA_ga", roleSystem: "EntraID", roleDefinitionName: "Global Administrator", scopeName: "Tenant", pimAssignmentType: "Eligible", tierName: "ControlPlane", services: ["Identity"] }],
            assignmentSummary: summary({ ControlPlane: 1 }, 1, 0)
        }),
        object({
            objectId: servicePrincipalId, objectType: "serviceprincipal", objectSubType: "Application", displayName: "App B",
            userPrincipalName: "aaaaaaaa-0000-0000-0000-000000000000", tierName: "ManagementPlane", tierLevel: "1",
            restrictedManagement: "Not available", owners: [ownerId, userId],
            assignments: [{ id: "EO_RA_pra", roleSystem: "EntraID", roleDefinitionName: "Privileged Role Administrator", scopeName: "Tenant", pimAssignmentType: "Permanent", tierName: "ControlPlane", services: ["Privileged Access"] }],
            assignmentSummary: summary({ ControlPlane: 1 }, 0, 1)
        }),
        object({
            objectId: groupId, objectType: "group", objectSubType: "Role-assignable", displayName: "PRG-Tier0-Admins", tierName: "Unclassified",
            restrictedManagement: "Applied", restrictedManagementByRAG: true, owners: [ownerId],
            assignments: [{ id: "EO_RA_sec", roleSystem: "EntraID", roleDefinitionName: "Security Administrator", scopeName: "Tenant", pimAssignmentType: "Eligible", tierName: "ControlPlane", services: ["Security"] }],
            assignmentSummary: summary({ ControlPlane: 1 }, 1, 0)
        }),
        object({
            objectId: "77777777-7777-7777-7777-777777777777", objectType: "user", objectSubType: "Guest", displayName: "=Guest D",
            userPrincipalName: "d_fabrikam.com#EXT#@contoso.com", tierName: "Unclassified", isForeign: true,
            assignmentSummary: summary({ ManagementPlane: 1 }, 1, 0)
        })
    ],
    relatedObjects: {
        [ownerId]: { objectId: ownerId, displayName: "Helpdesk Owner", objectType: "user", tierName: "", source: "Microsoft Graph" },
        "44444444-4444-4444-4444-444444444444": { objectId: "44444444-4444-4444-4444-444444444444", displayName: "LAPTOP-1", objectType: "device", operatingSystem: "Windows", isCompliant: false, source: "Microsoft Graph" }
    }
};

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-privileged-assets-browser-"));
    await mkdir(join(fixtureRoot, "Reports"), { recursive: true });
    await cp(join(reportsSourceDir, "shared"), join(fixtureRoot, "Reports", "shared"), { recursive: true });
    const csaData = {
        ...fixtureData,
        classificationSettings: {
            ...fixtureData.classificationSettings,
            customSecurityAttributes: { ...fixtureData.classificationSettings.customSecurityAttributes, enabledFor: { user: true, servicePrincipal: true, application: true } },
            alternateObjectTierLevelAttributes: { user: true, servicePrincipal: false, group: true },
            objectClassificationFile: { enabled: false, filePath: "./Classification/ObjectClassification.json", error: "", entries: fixtureData.classificationSettings.objectClassificationFile.entries }
        }
    };
    const mixedData = {
        ...fixtureData,
        classificationSettings: {
            ...fixtureData.classificationSettings,
            customSecurityAttributes: { ...fixtureData.classificationSettings.customSecurityAttributes, enabledFor: { user: true, servicePrincipal: true, application: true } }
        }
    };
    appUrl = await writeAppFixture("PrivilegedAssets", fixtureData);
    csaAppUrl = await writeAppFixture("PrivilegedAssetsCsa", csaData);
    mixedAppUrl = await writeAppFixture("PrivilegedAssetsMixed", mixedData);
});

async function writeAppFixture(folderName, data) {
    const appFixtureDir = join(fixtureRoot, "Reports", folderName);
    await cp(appSourceDir, appFixtureDir, {
        recursive: true,
        filter: (source) => {
            const sourceRelativePath = relative(appSourceDir, source);
            if (!sourceRelativePath) return true;
            return sourceRelativePath.split(sep)[0] !== "data" && !sourceRelativePath.endsWith(".spec.mjs") && sourceRelativePath !== ".DS_Store";
        }
    });
    await mkdir(join(appFixtureDir, "data"), { recursive: true });
    await writeFile(join(appFixtureDir, "data", "privileged-assets-data.js"), `window.ENTRAOPS_PRIVILEGED_ASSETS_DATA = ${JSON.stringify(data)};\n`, "utf8");
    return pathToFileURL(join(appFixtureDir, "index.html")).href;
}

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

async function openApp(page, url = appUrl) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(url);
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    await expect(page.locator("#paiTableBody tr")).toHaveCount(4);
    return pageErrors;
}

async function openClassification(page) {
    await page.click('.nav-subitem[data-view-nav="classification"]');
    await expect(page).toHaveURL(/\?view=classification$/);
    await expect(page.locator("#secPaiWorklist")).toBeVisible();
    await expect(page.locator("#secPaiInventory")).toBeHidden();
}

test("lists privileged objects with tier and relationship findings", async ({ page }) => {
    const pageErrors = await openApp(page);

    const appRow = page.locator(`#paiTableBody tr[data-object="${servicePrincipalId}"]`);
    await expect(appRow).toContainText("Object tier below role assignments");
    await expect(appRow).toContainText("Owner with lower tier");
    await expect(page.locator(`#paiTableBody tr[data-object="${userId}"]`)).toContainText("Synchronized Control Plane identity");
    await expect(page.locator(`#paiTableBody tr[data-object="${userId}"]`)).toContainText("Owns non-PAW devices");

    await page.selectOption("#paiFilterAu", "au1");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(1);
    await page.click("#paiResetFilters");
    await page.selectOption("#paiFilterFinding", "__relationship");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(2);
    expect(pageErrors).toEqual([]);
});

test("side panel links role assignments to the EAM Dashboard and the object to Access Path Map", async ({ page }) => {
    await openApp(page);
    await page.click(`#paiTableBody button[data-open="${servicePrincipalId}"]`);

    const drawer = page.locator("#paiDrawer");
    await expect(drawer).toHaveClass(/open/);
    await expect(drawer).toContainText("Helpdesk Owner");
    await expect(drawer.locator('a[href="../EamDashboard/index.html#assignment=EO_RA_pra"]')).toHaveCount(1);
    await expect(drawer.locator(`a[href="../EamDashboard/index.html#asset=${servicePrincipalId}"]`)).toHaveCount(1);
    await expect(drawer.locator(`a[href="../AccessPathMap/index.html#node=${servicePrincipalId.toUpperCase()}"]`)).toHaveCount(1);
    await expect(page).toHaveURL(new RegExp(`#asset=${servicePrincipalId}$`));
});

test("custom security attribute method exports a guarded CSV and generates a script without groups", async ({ page }) => {
    await openApp(page, csaAppUrl);
    await page.evaluate(() => {
        window.__downloads = [];
        const createObjectURL = URL.createObjectURL;
        URL.createObjectURL = (blob) => { blob.text().then((text) => window.__downloads.push(text)); return createObjectURL(blob); };
    });

    for (const id of [userId, servicePrincipalId, groupId, "77777777-7777-7777-7777-777777777777"]) {
        await page.check(`#paiTableBody input[data-select="${id}"]`);
    }
    await page.selectOption("#paiBulkTier", "ControlPlane");
    await page.fill("#paiBulkJustification", "Holds PRA");
    await page.click("#paiBulkAdd");
    await openClassification(page);
    await expect(page.locator("#paiWorklistMeta")).toContainText("4 entries");
    await expect(page.locator("#paiFileStatus")).toContainText("custom security attributes; Alternate Tier Level Attributes for users, groups");
    await expect(page.locator("#paiExportFile")).toBeHidden();
    await expect(page.locator("#paiResetWorklist")).toBeHidden();
    await expect(page.locator("#secPaiScript")).toBeVisible();
    await expect(page.locator("#paiScriptCrossTenant")).toBeVisible();
    await expect(page.locator("#paiScriptCrossTenant")).toContainText("1 object(s) not included in the script");
    await expect(page.locator("#paiScriptCrossTenant")).toContainText("=Guest D");

    await page.click("#paiExportCsv");
    await expect.poll(() => page.evaluate(() => window.__downloads.length)).toBe(1);
    const csv = await page.evaluate(() => window.__downloads[0]);
    expect(csv).toContain(`"${servicePrincipalId}","serviceprincipal","App B","ControlPlane","Holds PRA"`);
    expect(csv).toContain(`"'=Guest D"`);

    await page.click("#paiGenerateScript");
    const script = await page.inputValue("#paiScript");
    expect(script).toContain(`Uri = 'servicePrincipals/${servicePrincipalId}'`);
    expect(script).toContain(`Uri = 'users/${userId}'`);
    expect(script).not.toContain("Uri = 'users/77777777-7777-7777-7777-777777777777'");
    expect(script).toContain("_Guest D (77777777-7777-7777-7777-777777777777): belongs to another tenant");
    expect(script).not.toContain(`Uri = 'groups/`);
    expect(script).toContain("groups don't support custom security attributes");
    expect(script).toContain("Set = 'privilegedWorkloadIdentity'");
    expect(script).toContain("@('Integer', 'String')");
    expect(script).toContain("= '#Int32'");
    expect(script).toContain("function Set-EntraOpsAdminTierAttribute {");
    expect(script.trimEnd().endsWith("Set-EntraOpsAdminTierAttribute")).toBe(true);
    await expect(page.locator("#paiScriptWarning")).toBeHidden();
});

test("Object Classification File method hides the custom security attribute script", async ({ page }) => {
    const pageErrors = await openApp(page);
    await openClassification(page);

    await expect(page.locator("#paiFileStatus")).toContainText("Classification sources: Object Classification File");
    await expect(page.locator("#paiFileStatus")).not.toContainText("custom security attributes");
    await expect(page.locator("#paiExportFile")).toBeVisible();
    await expect(page.locator("#secPaiScript")).toBeHidden();
    await expect(page.locator('.section-item[data-target="secPaiScript"]')).toBeHidden();
    expect(pageErrors).toEqual([]);
});

test("combines the Object Classification File and custom security attributes", async ({ page }) => {
    const pageErrors = await openApp(page, mixedAppUrl);
    await page.check(`#paiTableBody input[data-select="${servicePrincipalId}"]`);
    await page.selectOption("#paiBulkTier", "ControlPlane");
    await page.click("#paiBulkAdd");
    await openClassification(page);

    await expect(page.locator("#paiFileStatus")).toContainText("file entries only apply to objects that the other sources don't classify");
    await expect(page.locator("#paiExportFile")).toBeVisible();
    await expect(page.locator("#secPaiScript")).toBeVisible();

    await page.click("#paiGenerateScript");
    const script = await page.inputValue("#paiScript");
    expect(script).toContain(`Uri = 'servicePrincipals/${servicePrincipalId}'`);
    expect(script).toContain(`Uri = 'users/${userId}'`);
    expect(pageErrors).toEqual([]);
});

test("Object Classification view shows current, target and highest-tier role assignments and edits entries inline", async ({ page }) => {
    const pageErrors = await openApp(page);
    await openClassification(page);

    const userRow = page.locator(`#paiWorklistBody tr[data-worklist="${userId}"]`);
    await expect(userRow).toContainText("Unclassified");
    await expect(userRow).toContainText("Global Administrator");
    await expect(userRow.locator('a[href="../EamDashboard/index.html#assignment=EO_RA_ga"]')).toHaveCount(1);
    await expect(userRow.locator(`select[data-target-tier="${userId}"]`)).toHaveValue("ControlPlane");

    await userRow.locator(`select[data-target-tier="${userId}"]`).selectOption("ManagementPlane");
    await userRow.locator(`input[data-justification="${userId}"]`).fill("Downgraded after review");
    await userRow.locator(`input[data-justification="${userId}"]`).press("Tab");
    await expect(userRow).toContainText("Changed");

    await page.fill("#paiAddObject", `App B (${servicePrincipalId})`);
    await page.selectOption("#paiAddTier", "ControlPlane");
    await page.click("#paiAddButton");
    const appRow = page.locator(`#paiWorklistBody tr[data-worklist="${servicePrincipalId}"]`);
    await expect(appRow).toContainText("Privileged Role Administrator");
    await expect(appRow).toContainText("Added");

    const stored = await page.evaluate(() => JSON.parse(localStorage.getItem("entraops.privilegedAssets.objectClassification.v1")).entries);
    expect(stored[userId].adminTierLevelName).toBe("ManagementPlane");
    expect(stored[userId].justification).toBe("Downgraded after review");

    await page.goBack();
    await expect(page.locator("#secPaiInventory")).toBeVisible();
    expect(pageErrors).toEqual([]);
});

test("import validates object ids, tier names and object types", async ({ page }) => {
    await openApp(page);
    await openClassification(page);
    const csv = [
        '"ObjectId","ObjectType","ObjectDisplayName","AdminTierLevelName","Justification"',
        `"${groupId}","group","PRG","managementplane","'=Imported"`,
        '"not-a-guid","user","X","ControlPlane",""',
        `"${userId}","group","Admin A","ControlPlane",""`,
        '"88888888-8888-8888-8888-888888888888","","Gone","Tier0",""'
    ].join("\r\n");
    await page.setInputFiles("#paiImport", { name: "import.csv", mimeType: "text/csv", buffer: Buffer.from(csv) });

    await expect(page.locator("#paiImportResult")).toContainText("Imported 1 entries");
    await expect(page.locator("#paiImportResult")).toContainText("is not a GUID");
    await expect(page.locator("#paiImportResult")).toContainText("does not match the inventory object type");
    await expect(page.locator("#paiImportResult")).toContainText("'Tier0' is not one of");
    const entry = await page.evaluate((id) => JSON.parse(localStorage.getItem("entraops.privilegedAssets.objectClassification.v1")).entries[id], groupId);
    expect(entry.adminTierLevelName).toBe("ManagementPlane");
    expect(entry.justification).toBe("=Imported");
});

for (const viewport of [{ name: "desktop", width: 1600, height: 900 }, { name: "laptop", width: 1175, height: 800 }]) {
    test(`${viewport.name} keeps the inventory inside the viewport`, async ({ page }) => {
        await page.setViewportSize(viewport);
        await openApp(page);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow).toBeLessThanOrEqual(1);
    });
}
