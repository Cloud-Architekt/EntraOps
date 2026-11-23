import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Filters of the PIM Request Flow: the search bar (search, snapshot, requirement and risk flag dropdowns, reset), the
// facet pills (assignment path, role access level, activation approval) with the number of matching assignment paths,
// and the collapsible groups of the risk flag list. Synthetic data only.

const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
const generatedAt = "2026-01-01T00:00:00Z";
const roles = {
    ga: "00000000-0000-0000-0000-000000000101",
    helpdesk: "00000000-0000-0000-0000-000000000102",
    reader: "00000000-0000-0000-0000-000000000103",
    custom: "00000000-0000-0000-0000-000000000104"
};

const blobs = {};
function roleSetting(folder, roleId, displayName, properties) {
    const hash = `h${Object.keys(blobs).length + 1}`;
    blobs[hash] = {
        resourceType: "microsoft.entra.rolesetting", displayName, properties: {
            Id: roleId, DisplayName: displayName, ActivationReqMFA: false, ApprovaltoActivate: false, ActivateApprover: [],
            PermanentEligibleAssignmentisExpirationRequired: true, PermanentActiveAssignmentisExpirationRequired: true, ...properties
        }
    };
    return { p: `microsoft.entra.rolesetting/${folder}/${displayName}.json`, h: hash };
}

// Four roles with three assignment paths each: 12 paths. Approval is required only to activate Helpdesk and Custom.
// MFA required: Helpdesk activation + active assignment, Reader activation, Custom activation.
const globalAdmin = roleSetting("Global", roles.ga, "Global Administrator", { ActivationReqJustification: true, ElegibilityAssignmentReqJustification: true, AssignmentReqJustification: true });
const latestResources = [
    globalAdmin,
    roleSetting("Helpdesk", roles.helpdesk, "Helpdesk Administrator", { ActivationReqMFA: true, ApprovaltoActivate: true, ActivateApprover: ["approver@contoso.com"], AssignmentReqMFA: true }),
    roleSetting("Reader", roles.reader, "Reports Reader", { ActivationReqMFA: true }),
    roleSetting("Custom", roles.custom, "Contoso Custom Role", { ActivationReqMFA: true, ActivationReqTicket: true, ApprovaltoActivate: true, ActivateApprover: ["approver@contoso.com"] })
];

const configurationAnalyzerData = {
    generatedAt,
    snapshots: [
        { commitSha: "aaaaaaaa", commitDate: "2026-01-01T08:00:00Z", subject: "older", hasDetail: true, resources: [globalAdmin] },
        { commitSha: "bbbbbbbb", commitDate: "2026-01-02T08:00:00Z", subject: "latest", hasDetail: true, resources: latestResources }
    ],
    blobs
};

const latestKey = "bbbbbbbb|2026-01-02T08:00:00Z";
const findings = {
    schemaVersion: 2,
    sources: { configurationAnalyzer: generatedAt, eam: null, tierMap: null },
    snapshots: {
        [latestKey]: {
            flags: {
                [`${roles.ga}|activation`]: [
                    { id: "noMfaActivation", severity: "fail", text: "Control Plane role can be activated without MFA." },
                    { id: "noApprovalActivation", severity: "fail", text: "Control Plane role can be activated without approval." }
                ],
                [`${roles.helpdesk}|activeAssignment`]: [{ id: "permanentActive", severity: "warn", text: "Permanent active assignment is allowed." }]
            },
            roles: {
                [roles.ga]: { tier: "ControlPlane", service: "Global" },
                [roles.helpdesk]: { tier: "ManagementPlane", service: "Users" },
                [roles.reader]: { tier: "UserAccess", service: "Reports" }
            }
        }
    }
};

let fixtureRoot;
let appUrl;

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-pim-request-flow-"));
    const reportsRoot = join(fixtureRoot, "Reports");
    for (const folder of ["shared", "ConfigurationAnalyzer", "PimRequestFlow"]) {
        const source = join(reportsSourceDir, folder);
        await cp(source, join(reportsRoot, folder), {
            recursive: true,
            filter: (path) => relative(source, path).split(sep)[0] !== "data" && !path.endsWith(".spec.mjs")
        });
    }
    const write = async (file, variable, data) => {
        await mkdir(join(reportsRoot, file, ".."), { recursive: true });
        await writeFile(join(reportsRoot, file), `window.${variable} = ${JSON.stringify(data)};\n`, "utf8");
    };
    await write("ConfigurationAnalyzer/data/configuration-analyzer-data.js", "ENTRAOPS_CONFIGANALYZER_DATA", configurationAnalyzerData);
    await write("PimRequestFlow/data/pim-request-flow-findings.js", "ENTRAOPS_PIM_REQUEST_FLOW_FINDINGS", findings);
    appUrl = pathToFileURL(join(reportsRoot, "PimRequestFlow", "index.html")).href;
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

async function openApp(page, hash = "") {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(appUrl);
    await page.evaluate(() => localStorage.clear());
    await page.goto(appUrl + hash);
    await page.reload();
    await expect(page.locator("#pimFilterSummary")).toContainText("of 12 assignment path(s) shown");
    return pageErrors;
}

// The pills of a facet as "label count" (disabled pills marked with "-", the active one with "*").
async function pills(page, id) {
    return page.locator(`#${id} .eo-pill`).evaluateAll((buttons) => buttons.map((button) =>
        (button.classList.contains("active") ? "*" : "") + (button.disabled ? "-" : "") +
        button.querySelector("span:not(.eo-pill-count):not(.eo-tier-dot)").textContent + " " + button.querySelector(".eo-pill-count").textContent));
}

const summary = (page) => page.locator("#pimFilterSummary");

test("PIM Request Flow shows the facet pills with the number of matching assignment paths", async ({ page }) => {
    const pageErrors = await openApp(page);
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");
    expect(await pills(page, "pimPathToggles")).toEqual(["*All 12", "Activation 4", "Eligible assignment 4", "Active assignment 4"]);
    // Workload Plane is not shown without roles of that tier.
    expect(await pills(page, "pimTierPills")).toEqual(["*All 12", "Control Plane 3", "Management Plane 3", "User Access 3", "Unclassified 3"]);
    expect(await pills(page, "pimApprovalPills")).toEqual(["*All 12", "Approval required 2", "No approval required 10"]);
    await expect(page.locator("#pimTierPills .eo-pill-tier.eo-tier-controlplane .eo-tier-dot")).toHaveCount(1);
    // The old dropdowns are gone; the dropdowns with many values sit in the search bar.
    await expect(page.locator("#pimFltTier, #pimFltApproval")).toHaveCount(0);
    await expect(page.locator(".eo-searchbar .eo-select #pimSnapshot")).toHaveCount(1);
    await expect(page.locator(".eo-searchbar #pimResetFilters")).toHaveCount(1);
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow filters by a pill, updates the counts of the other facets and resets on a second click", async ({ page }) => {
    const pageErrors = await openApp(page);
    await page.locator("#pimApprovalPills .eo-pill", { hasText: /^Approval required/ }).click();
    await expect(summary(page)).toHaveText(" · 2 of 12 assignment path(s) shown");
    expect(await pills(page, "pimApprovalPills")).toEqual(["All 12", "*Approval required 2", "No approval required 10"]);
    expect(await pills(page, "pimTierPills")).toEqual(["*All 2", "-Control Plane 0", "Management Plane 1", "-User Access 0", "Unclassified 1"]);
    expect(await pills(page, "pimPathToggles")).toEqual(["*All 2", "Activation 2", "-Eligible assignment 0", "-Active assignment 0"]);
    await expect(page.locator("#pimApprovalPills .eo-pill.active")).toHaveAttribute("aria-pressed", "true");

    // Both filters together.
    await page.locator("#pimTierPills .eo-pill", { hasText: "Management Plane" }).click();
    await expect(summary(page)).toHaveText(" · 1 of 12 assignment path(s) shown");
    expect(await pills(page, "pimApprovalPills")).toEqual(["All 3", "*Approval required 1", "No approval required 2"]);

    // A second click on the active pill shows all again.
    await page.locator("#pimApprovalPills .eo-pill", { hasText: /^Approval required/ }).click();
    await page.locator("#pimTierPills .eo-pill", { hasText: "Management Plane" }).click();
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");
    expect(await pills(page, "pimApprovalPills")).toEqual(["*All 12", "Approval required 2", "No approval required 10"]);

    // Pills work with the keyboard.
    await page.locator("#pimTierPills .eo-pill", { hasText: "Control Plane" }).focus();
    await page.keyboard.press("Enter");
    await expect(summary(page)).toHaveText(" · 3 of 12 assignment path(s) shown");
    expect(await pills(page, "pimApprovalPills")).toEqual(["*All 3", "-Approval required 0", "No approval required 3"]);
    await expect(page.locator("#pimTierPills .eo-pill.active")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");
    await page.locator("#pimPathToggles .eo-pill", { hasText: "Activation" }).focus();
    await page.keyboard.press("Space");
    await expect(summary(page)).toHaveText(" · 4 of 12 assignment path(s) shown");
    await expect(page.locator('#pimPathToggles [data-value="activation"]')).toBeFocused();
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow selects several assignment paths and returns to all", async ({ page }) => {
    const pageErrors = await openApp(page);
    const path = (text) => page.locator("#pimPathToggles .eo-pill", { hasText: text });
    await path("Activation").click();
    await path("Active assignment").click();
    await expect(summary(page)).toHaveText(" · 8 of 12 assignment path(s) shown");
    // The counts of a multi-select facet leave out its own selection.
    expect(await pills(page, "pimPathToggles")).toEqual(["All 12", "*Activation 4", "Eligible assignment 4", "*Active assignment 4"]);
    expect(await pills(page, "pimTierPills")).toEqual(["*All 8", "Control Plane 2", "Management Plane 2", "User Access 2", "Unclassified 2"]);
    await expect(path("Activation")).toHaveAttribute("aria-pressed", "true");

    // Deselecting the last selected path returns to all paths.
    await path("Activation").click();
    await expect(summary(page)).toHaveText(" · 4 of 12 assignment path(s) shown");
    await path("Active assignment").click();
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");
    expect(await pills(page, "pimPathToggles")).toEqual(["*All 12", "Activation 4", "Eligible assignment 4", "Active assignment 4"]);

    // "All" clears the selection.
    await path("Eligible assignment").click();
    await path("Activation").click();
    await expect(summary(page)).toHaveText(" · 8 of 12 assignment path(s) shown");
    await path(/^All/).click();
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow switches the columns of the flow, keeping at least two", async ({ page }) => {
    const pageErrors = await openApp(page);
    const column = (text) => page.locator("#pimFacets #pimColToggles .eo-pill-toggle", { hasText: text });
    await expect(page.locator("#pimColToggles .eo-pill-toggle.active")).toHaveCount(5);
    await expect(page.locator("#pimColToggles .eo-pill-count")).toHaveCount(0);
    await expect(page.locator("#pimSankey")).toContainText("NOTIFICATION");

    await column("Notification").click();
    await expect(column("Notification")).toHaveAttribute("aria-pressed", "false");
    await expect(column("Notification")).toBeFocused();
    await expect(page.locator("#pimSankey")).not.toContainText("NOTIFICATION");
    // Columns are a view option: the filters and their counts stay.
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");

    await column("Requirement").click();
    await column("Approval").click();
    await expect(page.locator("#pimColToggles .eo-pill-toggle.active")).toHaveCount(2);
    await column("Role").click();
    await expect(column("Role")).toHaveAttribute("aria-pressed", "true");
    await column("Notification").focus();
    await page.keyboard.press("Enter");
    await expect(column("Notification")).toHaveAttribute("aria-pressed", "true");
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow keeps the dropdown filters, the search and the reset", async ({ page }) => {
    const pageErrors = await openApp(page);
    await page.selectOption("#pimFltRequirement", "MFA required");
    await expect(summary(page)).toHaveText(" · 4 of 12 assignment path(s) shown");
    expect(await pills(page, "pimApprovalPills")).toEqual(["*All 4", "Approval required 2", "No approval required 2"]);
    await page.selectOption("#pimFltRequirement", "");

    await page.selectOption("#pimFltFlag", "noMfaActivation");
    await expect(summary(page)).toHaveText(" · 1 of 12 assignment path(s) shown");
    expect(await pills(page, "pimTierPills")).toEqual(["*All 1", "Control Plane 1", "-Management Plane 0", "-User Access 0", "-Unclassified 0"]);
    await page.selectOption("#pimFltFlag", "");

    await page.fill("#pimFltSearch", "helpdesk");
    await expect(summary(page)).toHaveText(" · 3 of 12 assignment path(s) shown");
    expect(await pills(page, "pimApprovalPills")).toEqual(["*All 3", "Approval required 1", "No approval required 2"]);

    await page.locator("#pimApprovalPills .eo-pill", { hasText: "No approval required" }).click();
    await page.locator("#pimPathToggles .eo-pill", { hasText: "Active assignment" }).click();
    await page.selectOption("#pimFltRequirement", "MFA required");
    await expect(summary(page)).toHaveText(" · 1 of 12 assignment path(s) shown");
    await page.click("#pimResetFilters");
    await expect(summary(page)).toHaveText(" · 12 of 12 assignment path(s) shown");
    await expect(page.locator("#pimFltSearch")).toHaveValue("");
    await expect(page.locator("#pimFltRequirement")).toHaveValue("");
    expect(await pills(page, "pimApprovalPills")).toEqual(["*All 12", "Approval required 2", "No approval required 10"]);
    expect(await pills(page, "pimPathToggles")).toEqual(["*All 12", "Activation 4", "Eligible assignment 4", "Active assignment 4"]);

    // Another snapshot: one role, without findings.
    await page.selectOption("#pimSnapshot", "0");
    await expect(summary(page)).toHaveText(" · 3 of 3 assignment path(s) shown");
    expect(await pills(page, "pimTierPills")).toEqual(["*All 3", "-Control Plane 0", "-Management Plane 0", "-User Access 0", "Unclassified 3"]);
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow exports the filtered assignment paths", async ({ page }) => {
    const pageErrors = await openApp(page);
    await page.locator("#pimApprovalPills .eo-pill", { hasText: /^Approval required/ }).click();
    const [download] = await Promise.all([page.waitForEvent("download", (item) => item.suggestedFilename().endsWith(".csv")), page.click("#pimExportFiltered")]);
    const csv = await readFile(await download.path(), "utf8");
    const lines = csv.trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(lines.slice(1).every((line) => line.includes("Approval required"))).toBe(true);
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow keeps the deep link to an assignment path", async ({ page }) => {
    const pageErrors = await openApp(page, `#flow=${encodeURIComponent(`${roles.helpdesk}|activation`)}`);
    await expect(page.locator("#pimFlowDetail")).toBeVisible();
    await expect(page.locator("#pimFlowDetail")).toContainText("Helpdesk Administrator");
    await expect(summary(page)).toHaveText(" · 1 of 12 assignment path(s) shown");
    expect(await pills(page, "pimTierPills")).toEqual(["*All 12", "Control Plane 3", "Management Plane 3", "User Access 3", "Unclassified 3"]);
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow shows a notice for an unknown assignment path", async ({ page }) => {
    const pageErrors = await openApp(page, `#flow=${encodeURIComponent("00000000-0000-0000-0000-000000000000|activation")}`);
    await expect(page.locator("#eoDeepLinkNotice")).toBeVisible();
    await expect(page.locator("#eoDeepLinkNotice")).toContainText("Assignment path 00000000-0000-0000-0000-000000000000|activation was not found in the loaded snapshots.");
    await expect(page.locator("#pimFlowDetail")).toBeHidden();
    expect(pageErrors).toEqual([]);
});

test("PIM Request Flow collapses the groups of the risk flag list and remembers them", async ({ page }) => {
    const pageErrors = await openApp(page);
    const groups = page.locator("#pimFlagsBody .eo-group");
    await expect(groups).toHaveCount(2);
    // Group titles use the display names of the tiers.
    await expect(groups.locator(".eo-group-title")).toHaveText(["Control Plane", "Management Plane"]);
    await expect(page.locator("#pimFlagsBody .eo-group-body").first()).toBeVisible();

    await page.locator("#pimFlagsBody .eo-group-toggle", { hasText: "Control Plane" }).click();
    await expect(page.locator("#pimFlagsBody .eo-group").first()).toHaveClass(/collapsed/);
    await expect(page.locator("#pimFlagsBody .eo-group-toggle").first()).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator("#pimFlagsBody .eo-group-toggle").first()).toBeFocused();
    await page.reload();
    await expect(page.locator("#pimFlagsBody .eo-group").first()).toHaveClass(/collapsed/);
    // Collapsed groups are rendered, only hidden.
    await expect(page.locator("#pimFlagsBody .ca-gap-row")).toHaveCount(3);

    await expect(page.locator("#pimCollapseAllRiskGroups")).toHaveText("Collapse all");
    await page.click("#pimCollapseAllRiskGroups");
    await expect(page.locator("#pimFlagsBody .eo-group.collapsed")).toHaveCount(2);
    await expect(page.locator("#pimCollapseAllRiskGroups")).toHaveText("Expand all");
    await page.click("#pimCollapseAllRiskGroups");
    await expect(page.locator("#pimFlagsBody .eo-group.collapsed")).toHaveCount(0);

    await page.selectOption("#pimFlagGroup", "service");
    await expect(page.locator("#pimFlagsBody .eo-group-title")).toHaveText(["Global", "Users"]);
    await page.fill("#pimFlagSearch", "permanent");
    await expect(page.locator("#pimFlagsBody .eo-group-title")).toHaveText(["Users"]);
    expect(pageErrors).toEqual([]);
});
