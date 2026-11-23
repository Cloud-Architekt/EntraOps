import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const appSourceDir = fileURLToPath(new URL(".", import.meta.url));
const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
let fixtureRoot;
let appUrl;

function role(id, system, name, tier) {
    return { roleAssignmentId: id, roleSystem: system, roleDefinitionName: name, roleAssignmentType: "Direct", pimAssignmentType: "Eligible", classification: [{ adminTierLevelName: tier }] };
}

function asset(objectId, objectType, name, tier, system, roles) {
    return { objectId, objectType, objectDisplayName: name, objectAdminTierLevelName: tier, roleSystem: system, roleAssignments: roles };
}

const adminA = asset("aaaaaaaa-0000-0000-0000-000000000001", "user", "Admin A", "ControlPlane", "EntraID", [role("ra1", "EntraID", "Global Administrator", "ControlPlane")]);
const helpdeskB = asset("aaaaaaaa-0000-0000-0000-000000000002", "user", "Helpdesk B", "ManagementPlane", "EntraID", [role("ra2", "EntraID", "Helpdesk Administrator", "ManagementPlane")]);
const appC = asset("aaaaaaaa-0000-0000-0000-000000000003", "serviceprincipal", "App C", "ControlPlane", "Azure", [role("ra3", "Azure", "Owner", "ControlPlane")]);

function snapshot(sha, date, objects, tierBreaches) {
    const tiers = ["ControlPlane", "ManagementPlane", "UserAccess", "Unclassified"];
    return {
        commitSha: sha, commitDate: date, rbacSystems: ["Azure", "EntraID", "IdentityGovernance"], hasDetail: true, objects,
        totals: { assets: new Set(objects.map((o) => o.objectId)).size, users: objects.filter((o) => o.objectType === "user").length, roleAssignments: objects.reduce((sum, o) => sum + o.roleAssignments.length, 0), tierBreaches },
        objectTier: tiers.map((tier) => ({ tier, assets: objects.filter((o) => o.objectAdminTierLevelName === tier).length, users: objects.filter((o) => o.objectType === "user" && o.objectAdminTierLevelName === tier).length })),
        accessTier: tiers.map((tier) => ({ tier, roleAssignments: objects.reduce((sum, o) => sum + o.roleAssignments.filter((ra) => ra.classification[0].adminTierLevelName === tier).length, 0) }))
    };
}

// Two snapshots of contoso; the second one adds an Identity Governance role of Helpdesk B, a user and a group.
const historyData = {
    tenantName: "contoso.onmicrosoft.com",
    generatedAt: "2026-01-09T00:00:00Z",
    tierOrder: ["ControlPlane", "ManagementPlane", "WorkloadPlane", "UserAccess", "Unclassified"],
    rbacSystems: ["Azure", "EntraID", "IdentityGovernance"],
    snapshots: [
        snapshot("1111111111111111111111111111111111111111", "2026-01-01T08:00:00Z", [adminA, helpdeskB, appC], 0),
        snapshot("2222222222222222222222222222222222222222", "2026-01-08T08:00:00Z", [
            adminA, helpdeskB,
            asset(helpdeskB.objectId, "user", "Helpdesk B", "ManagementPlane", "IdentityGovernance", [role("ra4", "IdentityGovernance", "Access package manager", "ManagementPlane")]),
            appC,
            asset("aaaaaaaa-0000-0000-0000-000000000004", "user", "User D", "UserAccess", "EntraID", [role("ra5", "EntraID", "Directory Readers", "UserAccess")]),
            asset("aaaaaaaa-0000-0000-0000-000000000005", "group", "Group E", "Unclassified", "EntraID", [role("ra6", "EntraID", "User Administrator", "ManagementPlane")])
        ], 1)
    ]
};

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-privilege-history-browser-"));
    const reportsRoot = join(fixtureRoot, "Reports");
    const appFixtureDir = join(reportsRoot, "PrivilegeHistory");
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
    await writeFile(join(appFixtureDir, "data", "privilege-history-data.js"), `window.ENTRAOPS_PRIVILEGEHISTORY_DATA = ${JSON.stringify(historyData)};\n`, "utf8");
    // The target of "Open in EAM Dashboard Overview".
    await mkdir(join(reportsRoot, "EamDashboard"), { recursive: true });
    await writeFile(join(reportsRoot, "EamDashboard", "index.html"), "<!DOCTYPE html><title>EAM Dashboard</title>", "utf8");
    appUrl = pathToFileURL(join(appFixtureDir, "index.html")).href;
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

async function openApp(page) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(appUrl);
    await expect(page.locator("#tmContent")).toBeVisible();
    return pageErrors;
}

function pillCount(container, value) {
    return container.locator(`[data-value="${value}"] .eo-pill-count`);
}

test("filters the snapshot detail by RBAC system and tier level pills with live counts", async ({ page }) => {
    const pageErrors = await openApp(page);
    const systemPills = page.locator("#tmFltRoleSystem");
    const tierPills = page.locator("#tmFltTierLevel");
    const assetRows = page.locator("#tmSnapshotBody table").first().locator("tbody tr");

    // Before a snapshot is selected, the pills count the latest snapshot of the time range: distinct objects,
    // so Helpdesk B (listed for EntraID and IdentityGovernance) counts once in "All" and its tier.
    await expect(page.locator("#tmFacetScope")).toContainText("latest snapshot");
    await expect(page.locator("#tmFacetScope")).toContainText("each counted once across RBAC systems");
    await expect(pillCount(systemPills, "")).toHaveText("5");
    await expect(pillCount(systemPills, "Azure")).toHaveText("1");
    await expect(pillCount(systemPills, "EntraID")).toHaveText("4");
    await expect(pillCount(systemPills, "IdentityGovernance")).toHaveText("1");
    await expect(pillCount(tierPills, "")).toHaveText("5");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("2");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("1");
    await expect(pillCount(tierPills, "UserAccess")).toHaveText("1");
    await expect(pillCount(tierPills, "Unclassified")).toHaveText("1");
    await expect(tierPills.locator('[data-value="WorkloadPlane"]')).toBeDisabled();
    await expect(tierPills.locator('[data-value="ControlPlane"]')).toHaveClass(/eo-tier-controlplane/);

    // The time range dropdowns change the counted snapshot.
    await page.selectOption("#tmRangeTo", "0");
    await expect(pillCount(systemPills, "")).toHaveText("3");
    await expect(pillCount(systemPills, "EntraID")).toHaveText("2");
    await expect(page.locator("#tmChartAssets .tm-point")).toHaveCount(2);
    await page.click("#tmResetRange");
    await expect(page.locator("#tmRangeTo")).toHaveValue("1");
    await expect(pillCount(systemPills, "")).toHaveText("5");

    await page.locator('#tmChartAssets .tm-point[data-idx="1"]').first().dispatchEvent("click");
    await expect(page.locator("#tmFacetScope")).not.toContainText("latest snapshot");
    await expect(assetRows).toHaveCount(6);

    await systemPills.locator('[data-value="EntraID"]').click();
    await expect(assetRows).toHaveCount(4);
    await expect(systemPills.locator('[data-value="EntraID"]')).toHaveAttribute("aria-pressed", "true");
    await expect(pillCount(tierPills, "")).toHaveText("4");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("1");
    await expect(pillCount(tierPills, "ManagementPlane")).toHaveText("1");

    await tierPills.locator('[data-value="ControlPlane"]').click();
    await expect(assetRows).toHaveCount(1);
    await expect(assetRows.first()).toContainText("Admin A");
    await expect(pillCount(systemPills, "")).toHaveText("2");
    await expect(pillCount(systemPills, "Azure")).toHaveText("1");
    await expect(systemPills.locator('[data-value="IdentityGovernance"]')).toBeDisabled();

    // The pills are multi-select: EntraID + Azure, a second click removes a value, "All" clears them.
    await tierPills.locator('[data-value="ControlPlane"]').click();
    await expect(assetRows).toHaveCount(4);
    await systemPills.locator('[data-value="Azure"]').click();
    await expect(assetRows).toHaveCount(5);
    await expect(systemPills.locator('[data-value="EntraID"]')).toHaveAttribute("aria-pressed", "true");
    await expect(systemPills.locator('[data-value="Azure"]')).toHaveAttribute("aria-pressed", "true");
    await expect(systemPills.locator('[data-value=""]')).toHaveAttribute("aria-pressed", "false");
    await expect(pillCount(tierPills, "")).toHaveText("5");
    await expect(pillCount(tierPills, "ControlPlane")).toHaveText("2");
    await tierPills.locator('[data-value="ControlPlane"]').click();
    await tierPills.locator('[data-value="UserAccess"]').click();
    await expect(assetRows).toHaveCount(3);
    await expect(pillCount(systemPills, "")).toHaveText("3");
    await expect(pillCount(systemPills, "Azure")).toHaveText("1");
    await expect(pillCount(systemPills, "EntraID")).toHaveText("2");
    await tierPills.locator('[data-value="UserAccess"]').click();
    await expect(tierPills.locator('[data-value="ControlPlane"]')).toHaveAttribute("aria-pressed", "true");
    await systemPills.locator('[data-value="Azure"]').click();
    await expect(assetRows).toHaveCount(1);

    await systemPills.locator('[data-value=""]').click();
    await expect(assetRows).toHaveCount(2);
    await expect(systemPills.locator('[data-value=""]')).toHaveAttribute("aria-pressed", "true");
    await expect(systemPills.locator('[aria-pressed="true"]')).toHaveCount(1);

    // The role search narrows the rows and the counts.
    await page.fill("#tmFltRole", "owner");
    await expect(assetRows).toHaveCount(1);
    await expect(assetRows.first()).toContainText("App C");
    await expect(pillCount(systemPills, "")).toHaveText("1");
    await expect(pillCount(systemPills, "EntraID")).toHaveText("0");

    await page.fill("#tmFltRole", "");
    await tierPills.locator('[data-value="ControlPlane"]').click();
    await expect(assetRows).toHaveCount(6);
    expect(pageErrors).toEqual([]);
});

test("hands the selected RBAC systems and tier levels over to the EAM Dashboard", async ({ page }) => {
    const pageErrors = await openApp(page);
    await page.locator('#tmChartAssets .tm-point[data-idx="1"]').first().dispatchEvent("click");
    await page.locator('#tmFltRoleSystem [data-value="EntraID"]').click();
    await page.locator('#tmFltRoleSystem [data-value="Azure"]').click();
    await page.locator('#tmFltTierLevel [data-value="ControlPlane"]').click();
    await page.locator('#tmFltTierLevel [data-value="ManagementPlane"]').click();
    expect(pageErrors).toEqual([]);
    await page.click("#tmJumpToOverview");
    await page.waitForURL(/EamDashboard/);
    const params = new URL(page.url()).searchParams;
    expect(params.get("rs")).toBe("EntraID,Azure");
    expect(params.get("objectTier")).toBe("ControlPlane,ManagementPlane");
});

test("hands all RBAC systems and tier levels over as a wildcard", async ({ page }) => {
    await openApp(page);
    await page.locator('#tmChartAssets .tm-point[data-idx="1"]').first().dispatchEvent("click");
    await page.click("#tmJumpToOverview");
    await page.waitForURL(/EamDashboard/);
    expect(new URL(page.url()).search).toBe("?rs=*&objectTier=*");
});

test("compares two points in time from the snapshot dropdowns", async ({ page }) => {
    const pageErrors = await openApp(page);
    await expect(page.locator("#tmCompareCurrent")).toHaveValue("1");
    await page.click("#tmCompareRun");
    await expect(page.locator("#tmCompareResult")).toContainText("Assets added (2)");
    expect(pageErrors).toEqual([]);
});

const historyFile = () => join(fixtureRoot, "Reports", "PrivilegeHistory", "data", "privilege-history-data.js");
const eamFile = () => join(fixtureRoot, "Reports", "EamDashboard", "data", "eam-dashboard-data.js");
async function writeHistory(data) {
    await writeFile(historyFile(), `window.ENTRAOPS_PRIVILEGEHISTORY_DATA = ${JSON.stringify(data)};\n`, "utf8");
}

test("the snapshot of today's data shows no delta vs. today (counted like the generator)", async ({ page }) => {
    // Totals of the generator: assets without groups, users once, role assignments once per instance ID (else ID).
    const data = structuredClone(historyData);
    data.snapshots[1].totals = { ...data.snapshots[1].totals, assets: 4, users: 3, roleAssignments: 6 };
    await writeHistory(data);
    await mkdir(dirname(eamFile()), { recursive: true });
    await writeFile(eamFile(), `window.ENTRAOPS_EAM_DATA = ${JSON.stringify({ objects: historyData.snapshots[1].objects })};\n`, "utf8");
    try {
        const pageErrors = await openApp(page);
        await page.locator('#tmChartAssets .tm-point[data-idx="1"]').first().dispatchEvent("click");
        const tiles = page.locator("#tmSnapshotBody .eam-tile");
        for (const label of ["Privileged assets", "Users assigned", "Role assignments"]) {
            await expect(tiles.filter({ hasText: label }).locator(".tm-delta")).toHaveText("no change");
        }
        expect(pageErrors).toEqual([]);
    } finally {
        await rm(eamFile(), { force: true });
        await writeHistory(historyData);
    }
});

test("the tier breach chart says what it counts, unlike the EO.8002 finding", async ({ page }) => {
    await openApp(page);
    await expect(page.locator("#tmBreachNote")).toContainText("including delegated permissions and Microsoft first-party apps");
    await expect(page.locator("#tmBreachNote")).toContainText("EO.8002");
});

test("without git history the snapshot is the current export, with a hint that trends need history", async ({ page }) => {
    const data = structuredClone(historyData);
    data.historySource = "folder";
    data.snapshots = [{ ...data.snapshots[1], commitSha: "(current export)", workingTree: true }];
    await writeHistory(data);
    try {
        await openApp(page);
        await expect(page.locator("#tmFolderNote")).toBeVisible();
        await expect(page.locator("#tmFolderNote")).toContainText("without git history");
        await expect(page.locator("#tmCompareCurrent option").first()).toContainText("current export");
        await expect(page.locator("#tmCompareCurrent option").first()).not.toContainText("working tree");
    } finally {
        await writeHistory(historyData);
    }
});

test("hands the role search over to the EAM Dashboard search", async ({ page }) => {
    await openApp(page);
    await page.locator('#tmChartAssets .tm-point[data-idx="1"]').first().dispatchEvent("click");
    await page.fill("#tmFltRole", "Global");
    await page.waitForTimeout(250);
    await page.click("#tmJumpToOverview");
    await page.waitForURL(/EamDashboard/);
    expect(new URL(page.url()).searchParams.get("q")).toBe("global");
});
