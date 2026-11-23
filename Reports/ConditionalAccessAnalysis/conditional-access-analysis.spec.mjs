import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
const caType = "microsoft.entra.conditionalAccessPolicy";
const adminRoleId = "62e90394-69f5-4237-9190-012177145e10";
let fixtureRoot;
let appUrl;

// Synthetic Conditional Access policies of contoso (UTCM/M365DSC property names).
const policies = {
    mfaAdmins: { Id: "00000000-0000-0000-0000-00000000ca01", DisplayName: "CA001 Require MFA for admins", State: "enabled", IncludeRoles: [adminRoleId], IncludeApplications: ["All"], BuiltInControls: ["mfa"], ClientAppTypes: ["all"] },
    blockLegacy: { Id: "00000000-0000-0000-0000-00000000ca02", DisplayName: "CA002 Block legacy authentication", State: "enabled", IncludeUsers: ["All"], IncludeApplications: ["All"], BuiltInControls: ["block"], ClientAppTypes: ["exchangeActiveSync", "other"] },
    compliantDevice: { Id: "00000000-0000-0000-0000-00000000ca03", DisplayName: "CA003 Require compliant device", State: "enabledForReportingButNotEnforced", IncludeUsers: ["admin@contoso.com"], IncludeApplications: ["Office365"], IncludeLocations: ["AllTrusted"], BuiltInControls: ["compliantDevice"], ClientAppTypes: ["browser", "mobileAppsAndDesktopClients"] },
    guestMfa: { Id: "00000000-0000-0000-0000-00000000ca04", DisplayName: "CA004 Guest MFA", State: "disabled", IncludeUsers: ["GuestsOrExternalUsers"], IncludeApplications: ["All"], BuiltInControls: ["mfa"], ClientAppTypes: ["browser"] },
    signInFrequency: { Id: "00000000-0000-0000-0000-00000000ca05", DisplayName: "CA005 Sign-in frequency", State: "enabled", IncludeGroups: ["sg-contoso-users"], IncludeApplications: ["All"], SignInFrequencyIsEnabled: true, SignInFrequencyValue: 4, SignInFrequencyType: "hours", ClientAppTypes: ["all"] }
};

function resources(keys) {
    return keys.map((key) => ({ p: `${caType}/General/${key}.json`, h: key }));
}

const configurationData = {
    tenantName: "contoso.onmicrosoft.com",
    generatedAt: "2026-10-28T08:00:00Z",
    snapshots: [
        { commitSha: "aaaaaaaa11111111", commitDate: "2026-10-20T10:00:00Z", subject: "older", hasDetail: true, resources: resources(["mfaAdmins", "blockLegacy"]) },
        { commitSha: "bbbbbbbb22222222", commitDate: "2026-10-27T10:00:00Z", subject: "latest", hasDetail: true, resources: resources(Object.keys(policies)) }
    ],
    blobs: Object.fromEntries(Object.entries(policies).map(([key, properties]) => [key, { properties }]))
};

// The role of CA001 is Control Plane and the user of CA003 Management Plane; the group of CA005 is not classified (User Access).
const eamData = {
    objects: [
        {
            objectId: "11111111-1111-1111-1111-111111111111", objectDisplayName: "Admin A", objectUserPrincipalName: "admin@contoso.com", objectType: "user", objectAdminTierLevelName: "ManagementPlane",
            classification: [], roleAssignments: []
        },
        {
            objectId: "22222222-2222-2222-2222-222222222222", objectDisplayName: "Admin B", objectUserPrincipalName: "adminb@contoso.com", objectType: "user", objectAdminTierLevelName: "ControlPlane",
            classification: [], roleAssignments: [{ roleDefinitionId: adminRoleId, roleDefinitionName: "Global Administrator", classification: [{ adminTierLevelName: "ControlPlane", service: "Global" }] }]
        }
    ]
};

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-conditional-access-browser-"));
    const reports = join(fixtureRoot, "Reports");
    await mkdir(join(reports, "ConfigurationAnalyzer", "data"), { recursive: true });
    await mkdir(join(reports, "EamDashboard", "data"), { recursive: true });
    await cp(join(reportsSourceDir, "shared"), join(reports, "shared"), { recursive: true });
    await cp(join(reportsSourceDir, "ConfigurationAnalyzer", "js"), join(reports, "ConfigurationAnalyzer", "js"), { recursive: true });
    await cp(join(reportsSourceDir, "ConditionalAccessAnalysis"), join(reports, "ConditionalAccessAnalysis"), { recursive: true });
    await writeFile(join(reports, "ConfigurationAnalyzer", "data", "configuration-analyzer-data.js"), `window.ENTRAOPS_CONFIGANALYZER_DATA = ${JSON.stringify(configurationData)};\n`);
    await writeFile(join(reports, "EamDashboard", "data", "eam-dashboard-data.js"), `window.ENTRAOPS_EAM_DATA = ${JSON.stringify(eamData)};\n`);
    appUrl = pathToFileURL(join(reports, "ConditionalAccessAnalysis", "index.html")).href;
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

async function openApp(page, hash = "") {
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route((url) => !["file:", "data:", "blob:", "about:"].includes(url.protocol), (route) => route.abort());
    await page.goto(appUrl + hash);
    await expect(page.locator("#caContent")).toBeVisible();
    return errors;
}

function pill(page, containerId, label) {
    return page.locator(`#${containerId} .eo-pill`).filter({ hasText: label });
}

async function expectCount(page, containerId, label, count) {
    await expect(pill(page, containerId, label).locator(".eo-pill-count")).toHaveText(String(count));
}

async function expectShown(page, shown, total = 5) {
    await expect(page.locator("#caFilterSummary")).toHaveText(` · ${shown} of ${total} policy path(s) shown`);
}

test("filter pills render with the counts of the latest snapshot", async ({ page }) => {
    const errors = await openApp(page);
    await expectShown(page, 5);
    await expect(page.locator("#caSnapshot")).toHaveValue("1");

    await expectCount(page, "caStateToggles", "All", 5);
    await expectCount(page, "caStateToggles", "Enabled", 3);
    await expectCount(page, "caStateToggles", "Report-only", 1);
    await expectCount(page, "caStateToggles", "Disabled", 1);
    await expect(page.locator("#caStateToggles .eo-pill.active")).toHaveText(["All5"]);
    await expect(page.locator('#caStateToggles .eo-pill[data-multi="true"]')).toHaveCount(4);

    await expect(page.locator("#caGrantPills .eo-pill")).toHaveText(["All5", "Block access1", "Require MFA2", "Require compliant device1", "Session controls only1"]);
    await expect(pill(page, "caGrantPills", "All")).toHaveAttribute("aria-pressed", "true");

    await expectCount(page, "caClientAppPills", "Browser", 4);
    await expectCount(page, "caClientAppPills", "Mobile apps & desktop clients", 3);
    await expectCount(page, "caClientAppPills", "Exchange ActiveSync (legacy)", 3);
    await expectCount(page, "caClientAppPills", "Other clients (legacy auth)", 3);

    await expect(page.locator("#caAssignmentTierPills .eo-pill-tier")).toHaveCount(3);
    await expectCount(page, "caAssignmentTierPills", "Control Plane", 1);
    await expectCount(page, "caAssignmentTierPills", "Management Plane", 1);
    await expectCount(page, "caAssignmentTierPills", "User Access", 1);

    await expect(page.locator("#caColToggles .eo-pill-toggle.active")).toHaveCount(6);
    await expect(page.locator("#caColToggles .eo-pill-count")).toHaveCount(0);
    expect(errors).toEqual([]);
});

test("a pill filters the flow, updates the other facets and resets on a second click", async ({ page }) => {
    const errors = await openApp(page);
    const mfa = pill(page, "caGrantPills", "Require MFA");
    await mfa.click();
    await expectShown(page, 2);
    await expect(mfa).toHaveAttribute("aria-pressed", "true");
    // The grant facet keeps its own counts; the other facets count the MFA policies only.
    await expectCount(page, "caGrantPills", "Block access", 1);
    await expectCount(page, "caStateToggles", "Enabled", 1);
    await expectCount(page, "caStateToggles", "Report-only", 0);
    await expect(pill(page, "caStateToggles", "Report-only")).toBeDisabled();
    await expectCount(page, "caClientAppPills", "Browser", 2);
    await expectCount(page, "caClientAppPills", "Exchange ActiveSync (legacy)", 1);
    await expectCount(page, "caAssignmentTierPills", "Control Plane", 1);
    await expect(pill(page, "caAssignmentTierPills", "Management Plane")).toBeDisabled();

    await mfa.click();
    await expectShown(page, 5);
    await expect(pill(page, "caGrantPills", "All")).toHaveAttribute("aria-pressed", "true");
    await expectCount(page, "caStateToggles", "Report-only", 1);

    // Client app type: a policy for all client apps covers every type.
    await pill(page, "caClientAppPills", "Exchange ActiveSync (legacy)").click();
    await expectShown(page, 3);
    await expectCount(page, "caGrantPills", "Require MFA", 1);
    await expectCount(page, "caGrantPills", "Require compliant device", 0);

    // Access level is a tier pill and combines with the client app type.
    await pill(page, "caAssignmentTierPills", "Control Plane").click();
    await expectShown(page, 1);
    await expect(pill(page, "caAssignmentTierPills", "Control Plane")).toHaveClass(/eo-tier-controlplane/);
    await expectCount(page, "caClientAppPills", "Browser", 1);
    await pill(page, "caAssignmentTierPills", "All").click();
    await pill(page, "caClientAppPills", "All").click();
    await expectShown(page, 5);

    // Pills are buttons: Enter on the focused pill selects it.
    await pill(page, "caGrantPills", "Block access").focus();
    await page.keyboard.press("Enter");
    await expectShown(page, 1);
    expect(errors).toEqual([]);
});

test("policy state is a multi-select facet and follows the metric tiles", async ({ page }) => {
    const errors = await openApp(page);
    const all = pill(page, "caStateToggles", "All");
    await pill(page, "caStateToggles", "Enabled").click();
    await expectShown(page, 3);
    await expect(pill(page, "caStateToggles", "Enabled")).toBeFocused();
    await pill(page, "caStateToggles", "Disabled").click();
    await expectShown(page, 4);
    await expect(page.locator("#caStateToggles .eo-pill.active")).toHaveText(["Enabled3", "Disabled1"]);
    await expect(all).toHaveAttribute("aria-pressed", "false");
    // The state facet keeps its own counts; the other facets count the selected states only.
    await expectCount(page, "caStateToggles", "Report-only", 1);
    await expectCount(page, "caGrantPills", "Require MFA", 2);
    await expectCount(page, "caGrantPills", "Require compliant device", 0);
    await expectCount(page, "caGrantPills", "All", 4);

    // A second click removes a state; "All" clears the selection.
    await pill(page, "caStateToggles", "Enabled").click();
    await expectShown(page, 1);
    await expect(page.locator("#caStateToggles .eo-pill.active")).toHaveText(["Disabled1"]);
    await all.click();
    await expectShown(page, 5);
    await expect(page.locator("#caStateToggles .eo-pill.active")).toHaveText(["All5"]);

    // A metric tile selects its state in the pills, and a pill selection moves the tile highlight.
    const enabledTile = page.locator('[data-ca-metric="enabled"]');
    const allTile = page.locator('[data-ca-metric="all"]');
    await enabledTile.click();
    await expectShown(page, 3);
    await expect(enabledTile).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator("#caStateToggles .eo-pill.active")).toHaveText(["Enabled3"]);
    await pill(page, "caStateToggles", "Report-only").click();
    await expectShown(page, 4);
    await expect(enabledTile).toHaveAttribute("aria-pressed", "false");
    await expect(allTile).toHaveAttribute("aria-pressed", "false");
    await enabledTile.click();
    await expectShown(page, 3);
    await enabledTile.click();
    await expectShown(page, 5);
    await expect(allTile).toHaveAttribute("aria-pressed", "true");
    await expect(all).toHaveAttribute("aria-pressed", "true");
    expect(errors).toEqual([]);
});

test("dropdown filters, search, snapshot picker and reset still work", async ({ page }) => {
    const errors = await openApp(page);
    await page.locator("#caFltAssignment").selectOption("All users");
    await expectShown(page, 1);
    await expectCount(page, "caGrantPills", "Block access", 1);
    await expectCount(page, "caGrantPills", "Require MFA", 0);

    await page.locator("#caFltAssignment").selectOption("");
    await page.locator("#caFltNetwork").selectOption("All trusted locations");
    await expectShown(page, 1);
    await page.locator("#caFltNetwork").selectOption("");

    await page.locator("#caFltSearch").fill("guest");
    await expectShown(page, 1);
    await expectCount(page, "caStateToggles", "Disabled", 1);
    await expectCount(page, "caStateToggles", "Enabled", 0);

    // Reset clears the search, the dropdowns and every pill.
    await pill(page, "caStateToggles", "Disabled").click();
    await page.locator("#caFltCondition").selectOption({ index: 1 });
    await page.locator("#caResetFilters").click();
    await expectShown(page, 5);
    await expect(page.locator("#caFltSearch")).toHaveValue("");
    await expect(page.locator("#caFltCondition")).toHaveValue("");
    await expect(page.locator("#caFacets .eo-pill.active")).toHaveCount(1 + 1 + 1 + 1 + 6);

    // Another snapshot replaces the pills with its own values and resets the pill filters.
    await pill(page, "caGrantPills", "Require MFA").click();
    await page.locator("#caSnapshot").selectOption("0");
    await expectShown(page, 2, 2);
    await expect(page.locator("#caGrantPills .eo-pill")).toHaveText(["All2", "Block access1", "Require MFA1"]);
    await expect(pill(page, "caGrantPills", "All")).toHaveAttribute("aria-pressed", "true");
    expect(errors).toEqual([]);
});

test("the CSV export respects the filters and column pills toggle the flow columns", async ({ page }) => {
    const errors = await openApp(page);
    await pill(page, "caGrantPills", "Require MFA").click();
    const downloadPromise = page.waitForEvent("download");
    await page.locator("#caExportFiltered").click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("entraops-conditional-access-filtered.csv");
    const csv = await readFile(await download.path(), "utf8");
    const rows = csv.trim().split("\n");
    expect(rows).toHaveLength(3);
    expect(csv).toContain("CA001 Require MFA for admins");
    expect(csv).toContain("CA004 Guest MFA");

    const column = (name) => page.locator(`#caColToggles [data-toggle="column"][data-value="${name}"]`);
    await column("network").click();
    await expect(column("network")).toHaveAttribute("aria-pressed", "false");
    await expect(page.locator("#sankey text").filter({ hasText: /^NETWORK$/ })).toHaveCount(0);
    await column("network").click();
    await expect(page.locator("#sankey text").filter({ hasText: /^NETWORK$/ })).toHaveCount(1);
    // Column toggles don't change the filters, and a flow keeps at least two columns.
    await expectShown(page, 2);
    for (const name of ["assignment", "target", "network", "condition"]) await column(name).click();
    await expect(page.locator("#caColToggles .eo-pill-toggle.active")).toHaveText(["Policy", "Grant controls"]);
    await expect(column("policy")).toBeDisabled();
    await expect(column("grant")).toBeDisabled();
    await column("target").click();
    await expect(column("policy")).toBeEnabled();
    expect(errors).toEqual([]);
});

test("an unknown policy deep link shows a notice", async ({ page }) => {
    const errors = await openApp(page, "#flow=" + encodeURIComponent("00000000-0000-0000-0000-00000000ca99"));
    await expect(page.locator("#eoDeepLinkNotice")).toContainText("Conditional Access policy 00000000-0000-0000-0000-00000000ca99 was not found in the loaded snapshots.");
    await expect(page.locator("#caClearTrace")).toBeHidden();
    expect(errors).toEqual([]);
});

test("an object deep link opens the shared object inspector", async ({ page }) => {
    const errors = await openApp(page, "#object=" + encodeURIComponent("22222222-2222-2222-2222-222222222222"));
    await expect(page.locator("#objectInspector.open")).toBeVisible();
    await expect(page.locator("#objectInspectorTitle")).toContainText("Admin B");
    await page.locator("#objectInspectorClose").click();
    await expect(page.locator("#objectInspector.open")).toHaveCount(0);
    expect(await page.evaluate(() => location.hash)).toBe("");
    expect(errors).toEqual([]);
});

test("a policy deep link traces the policy", async ({ page }) => {
    const errors = await openApp(page, "#flow=" + encodeURIComponent(policies.compliantDevice.Id));
    await expect(page.locator("#caClearTrace")).toBeVisible();
    await expect(page.locator("#caPolicyDetail")).toContainText("CA003 Require compliant device");
    expect(errors).toEqual([]);
});

test("a policy deep link clears the filters that hide the policy and matches the ID case-insensitively", async ({ page }) => {
    const errors = await openApp(page);
    await page.locator("#caGrantPills .eo-pill", { hasText: "Block access" }).click();
    await page.evaluate((hash) => { location.hash = hash; }, "#flow=" + encodeURIComponent(policies.compliantDevice.Id.toUpperCase()));
    await expect(page.locator("#caPolicyDetail")).toContainText("CA003 Require compliant device");
    await expect(page.locator('#caGrantPills .eo-pill.active')).toHaveAttribute("data-value", "");
    expect(errors).toEqual([]);
});

test("without the EAM Dashboard dataset the access level facet says where the tiers come from", async ({ page }) => {
    const reports = join(fixtureRoot, "ReportsNoEam");
    await cp(join(fixtureRoot, "Reports"), reports, { recursive: true });
    await rm(join(reports, "EamDashboard"), { recursive: true, force: true });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route((url) => !["file:", "data:", "blob:", "about:"].includes(url.protocol), (route) => route.abort());
    await page.goto(pathToFileURL(join(reports, "ConditionalAccessAnalysis", "index.html")).href);
    await expect(page.locator("#caAssignmentTierPills .eo-facet-note")).toContainText("EAM Dashboard dataset");
    expect(errors).toEqual([]);
});
