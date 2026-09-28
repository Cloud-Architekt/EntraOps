import { expect, test } from "@playwright/test";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

for (const reportApp of ["AccessPackageFlow", "ConditionalAccessAnalysis", "ConfigurationAnalyzer", "PimRequestFlow"]) {
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
