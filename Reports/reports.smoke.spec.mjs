import { expect, test as base } from "@playwright/test";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Reports must work fully offline and must not send tenant data anywhere: every request that does not
// stay on the local file system fails the test.
const localProtocols = new Set(["file:", "data:", "blob:", "about:"]);
const test = base.extend({
    context: async ({ context }, use) => {
        const blockedRequests = [];
        await context.route((url) => !localProtocols.has(url.protocol), (route) => {
            blockedRequests.push(route.request().url());
            return route.abort("blockedbyclient");
        });
        await use(context);
        expect(blockedRequests, "Report pages must not request network resources").toEqual([]);
    }
});

const reportsRoot = fileURLToPath(new URL(".", import.meta.url));
const reportApps = [
    "AccessPackageFlow",
    "AccessPathMap",
    "ClassificationExplorer",
    "ConditionalAccessAnalysis",
    "ConfigurationAnalyzer",
    "EamDashboard",
    "EidscaCoverage",
    "PimRequestFlow",
    "PrivilegedAssets",
    "PrivilegeHistory",
    "TierBreachAnalyzer"
];
const reportPages = [
    { name: "Landing page", path: "index.html" },
    ...reportApps.map((reportApp) => ({ name: reportApp, path: join(reportApp, "index.html") }))
];

for (const reportPage of reportPages) {
    test(`${reportPage.name} renders its offline shell without an uncaught exception`, async ({ page }) => {
        const pageErrors = [];
        page.on("pageerror", (error) => pageErrors.push(error.message));

        const reportUrl = pathToFileURL(join(reportsRoot, reportPage.path)).href;
        await page.goto(reportUrl);

        await expect(page.locator("body")).toBeVisible();
        await expect(page).toHaveTitle(/\S/);
        expect(pageErrors).toEqual([]);
    });
}

for (const reportApp of ["AccessPackageFlow", "ConditionalAccessAnalysis", "ConfigurationAnalyzer", "PimRequestFlow", "PrivilegedAssets"]) {
    test(`${reportApp} section navigation resolves every target without an uncaught exception`, async ({ page }) => {
        const pageErrors = [];
        page.on("pageerror", (error) => pageErrors.push(error.message));

        const reportUrl = pathToFileURL(join(reportsRoot, reportApp, "index.html")).href;
        await page.goto(reportUrl);

        const navigationItems = page.locator(".nav-item.section-item");
        expect(await navigationItems.count()).toBeGreaterThan(0);
        for (const navigationItem of await navigationItems.all()) {
            const targetId = await navigationItem.getAttribute("data-target");
            expect(targetId).toBeTruthy();
            await expect(page.locator(`[id="${targetId}"]`)).toHaveCount(1);
            await navigationItem.dispatchEvent("click");
        }
        expect(pageErrors).toEqual([]);
    });
}

for (const reportApp of ["AccessPackageFlow", "ConditionalAccessAnalysis", "ConfigurationAnalyzer", "PimRequestFlow"]) {
    test(`${reportApp} treats section navigation targets as IDs rather than HTML`, async ({ page }) => {
        const pageErrors = [];
        page.on("pageerror", (error) => pageErrors.push(error.message));
        const reportUrl = pathToFileURL(join(reportsRoot, reportApp, "index.html")).href;
        await page.goto(reportUrl);

        const navigationItem = page.locator(".nav-item.section-item").first();
        await navigationItem.evaluate((item) => {
            item.setAttribute("data-target", '<img id="security-probe" src="invalid:" onerror="window.__navigationXss = true">');
        });
        await navigationItem.dispatchEvent("click");

        await expect(page.locator("#security-probe")).toHaveCount(0);
        expect(await page.evaluate(() => window.__navigationXss)).toBeUndefined();
        expect(pageErrors).toEqual([]);
    });
}

for (const reportApp of ["AccessPackageFlow", "ConditionalAccessAnalysis", "ConfigurationAnalyzer", "EidscaCoverage", "PimRequestFlow"]) {
    test(`${reportApp} keeps partial Tenant Governance health visible`, async ({ page }) => {
        const reportUrl = pathToFileURL(join(reportsRoot, reportApp, "index.html")).href;
        await page.goto(reportUrl);
        await page.evaluate(() => {
            window.DATA = {
                snapshotHealth: {
                    status: "partiallySuccessful",
                    isComplete: false,
                    capturedDateTime: "2026-01-01T00:00:00Z",
                    staleResourceTypes: ["microsoft.entra.conditionalaccesspolicy"],
                    resourceTypeStates: [{
                        resourceType: "microsoft.entra.conditionalaccesspolicy",
                        status: "PreservedStale",
                        publishedSnapshotId: "previous-snapshot"
                    }],
                    diagnostics: [{
                        resourceType: "microsoft.entra.conditionalaccesspolicy",
                        errorCategory: "ConnectionError",
                        occurrences: 2,
                        message: "Underlying workload was unavailable.",
                        remediationHint: "Retry the snapshot."
                    }]
                }
            };
            if (document.getElementById("caSnapshotHealth")) {
                window.renderEntraOpsSnapshotHealth("caSnapshotHealth");
            }
            window.renderEntraOpsSnapshotHealth();
        });
        const health = page.locator(".entraops-snapshot-health");
        await expect(health).toHaveCount(1);
        await expect(health).toBeVisible();
        await expect(health).toContainText("Partial Tenant Governance snapshot");
        await expect(health).toContainText("previous-snapshot");
        await expect(health).toContainText("Capture diagnostics (1)");
        await expect(health).toContainText("Retry the snapshot.");
        await expect(health.locator("button")).toHaveCount(0);
    });
}

for (const reportApp of ["ConfigurationAnalyzer", "PimRequestFlow"]) {
    test(`${reportApp} shows an outdated complete Tenant Governance snapshot`, async ({ page }) => {
        const reportUrl = pathToFileURL(join(reportsRoot, reportApp, "index.html")).href;
        await page.goto(reportUrl);
        await page.evaluate(() => {
            window.DATA = {
                snapshotHealth: {
                    status: "succeeded",
                    isComplete: true,
                    isStale: true,
                    ageHours: 200,
                    maxAgeHours: 174,
                    capturedDateTime: "2026-01-01T00:00:00Z",
                    staleResourceTypes: [],
                    resourceTypeStates: []
                }
            };
            if (document.getElementById("caSnapshotHealth")) {
                window.renderEntraOpsSnapshotHealth("caSnapshotHealth");
            }
            window.renderEntraOpsSnapshotHealth();
        });
        const health = page.locator(".entraops-snapshot-health");
        await expect(health).toHaveCount(1);
        await expect(health).toContainText("Outdated Tenant Governance snapshot");
        await expect(health).toContainText("8 days ago");
        await expect(health).toContainText("174-hour limit");
        await expect(health).not.toContainText("Partial Tenant Governance snapshot");
    });
}
