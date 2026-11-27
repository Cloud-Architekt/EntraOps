import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const appSourceDir = fileURLToPath(new URL(".", import.meta.url));
const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
let fixtureRoot;
let appUrl;

const helpdeskId = "aaaaaaaa-0000-0000-0000-000000000002";
const appId = "aaaaaaaa-0000-0000-0000-000000000003";

function breachPath(objectId, objectName, objectType, system, role, service, scopeId) {
    return {
        pathId: `${objectId}-${role}`, objectId, objectName, objectType, objectTier: 1, objectTierName: "ManagementPlane", system, role, roleType: "BuiltInRole",
        roleIsPrivileged: true, service, serviceTier: 0, assignmentInstanceId: `EO_RA_${objectId}`, assignmentId: objectId, scopeName: scopeId, scopeId,
        assignmentType: "Direct", assignmentSubType: "", pimManaged: true, pimAssignmentType: "Eligible", transitiveBy: "", tier0Breach: true, breach: true
    };
}

// Two Tier 0 breach paths of contoso: a Management Plane user and service principal reach Control Plane services.
const tierBreachData = {
    tenantName: "contoso.onmicrosoft.com",
    generatedFrom: ["PrivilegedEAM/EntraID/EntraID.json", "PrivilegedEAM/Azure/Azure.json"],
    tierLabels: { 0: "Tier 0 - Control Plane", 1: "Tier 1 - Management Plane", 2: "Tier 2 - User Access" },
    objects: [
        { id: helpdeskId, name: "Helpdesk B", type: "user", system: "EntraID", tier: 1 },
        { id: appId, name: "App C", type: "serviceprincipal", system: "Azure", tier: 1 }
    ],
    paths: [
        breachPath(helpdeskId, "Helpdesk B", "user", "EntraID", "Privileged Authentication Administrator", "Authentication", "/"),
        breachPath(appId, "App C", "serviceprincipal", "Azure", "Owner", "Azure Lighthouse", "/providers/Microsoft.Management/managementGroups/root")
    ],
    scopeReasoningByScope: {}
};

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-tier-breach-browser-"));
    const reportsRoot = join(fixtureRoot, "Reports");
    const appFixtureDir = join(reportsRoot, "TierBreachAnalyzer");
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
    await writeFile(join(appFixtureDir, "data", "tier-breach-data.js"), `window.ENTRAOPS_TB_DATA = ${JSON.stringify(tierBreachData)};\n`, "utf8");
    appUrl = pathToFileURL(join(appFixtureDir, "index.html")).href;
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

async function openApp(page, hash = "") {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(appUrl + hash);
    await expect(page.locator("#breachTable tbody tr.breach-row")).toHaveCount(2);
    return pageErrors;
}

function selLink(path) {
    return "#sel=" + encodeURIComponent([path.objectId, path.role, path.service, path.scopeId].join("||"));
}

test("a breach path deep link opens its row, also when the search hides it", async ({ page }) => {
    const [helpdeskPath, appPath] = tierBreachData.paths;
    const pageErrors = await openApp(page, selLink(helpdeskPath));
    await expect(page.locator("#breachTable tbody tr.breach-row.open")).toHaveCount(1);
    await expect(page.locator("#breachTable tbody tr.breach-row.open")).toContainText("Helpdesk B");

    // A search that hides the target row is cleared by the deep link.
    await page.fill("#search", "helpdesk");
    await expect(page.locator("#breachTable tbody tr.breach-row")).toHaveCount(1);
    await page.evaluate((hash) => { location.hash = hash; }, selLink(appPath));
    await expect(page.locator("#search")).toHaveValue("");
    await expect(page.locator("#breachTable tbody tr.breach-row")).toHaveCount(2);
    await expect(page.locator("#breachTable tbody tr.breach-row.open").filter({ hasText: "App C" })).toHaveCount(1);
    await expect(page.locator("#eoDeepLinkNotice")).toHaveCount(0);
    expect(pageErrors).toEqual([]);
});

test("an unknown breach path deep link shows a notice", async ({ page }) => {
    const pageErrors = await openApp(page, "#sel=" + encodeURIComponent(["99999999-9999-9999-9999-999999999999", "Owner", "Azure Lighthouse", "/"].join("||")));
    await expect(page.locator("#eoDeepLinkNotice")).toBeVisible();
    await expect(page.locator("#eoDeepLinkNotice")).toContainText("Tier breach path 99999999-9999-9999-9999-999999999999 / Owner / Azure Lighthouse / / was not found in the loaded breach paths.");
    await expect(page.locator("#breachTable tbody tr.breach-row.open")).toHaveCount(0);
    expect(pageErrors).toEqual([]);
});

test("a #path= deep link opens the breach path by its pathId", async ({ page }) => {
    const [helpdeskPath, appPath] = tierBreachData.paths;
    const pageErrors = await openApp(page, "#path=" + encodeURIComponent(appPath.pathId));
    await expect(page.locator("#breachTable tbody tr.breach-row.open")).toHaveCount(1);
    await expect(page.locator("#breachTable tbody tr.breach-row.open")).toContainText("App C");
    // A pathId in #sel= wins over the tuple, so two assignments with the same tuple are told apart.
    await page.evaluate((hash) => { location.hash = hash; }, "#sel=" + encodeURIComponent([appPath.objectId, appPath.role, appPath.service, appPath.scopeId, helpdeskPath.pathId].join("||")));
    await expect(page.locator("#breachTable tbody tr.breach-row.open").filter({ hasText: "Helpdesk B" })).toHaveCount(1);
    await page.evaluate((hash) => { location.hash = hash; }, "#path=unknown-path");
    await expect(page.locator("#eoDeepLinkNotice")).toContainText("Tier breach path unknown-path was not found");
    expect(pageErrors).toEqual([]);
});
