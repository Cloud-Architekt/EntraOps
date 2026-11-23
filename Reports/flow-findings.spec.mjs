import { expect, test } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// The risk flags and tiers of the PIM Request Flow and Access Package Flow reports are evaluated only in
// PowerShell (New-EntraOpsReportFindingData). This spec renders both reports for the same datasets twice - once
// with the findings that PowerShell generated and once without them - and expects the risk flags and tiers of
// the findings file, or a notice that they were not evaluated.

const reportsSourceDir = fileURLToPath(new URL(".", import.meta.url));
const moduleManifest = join(reportsSourceDir, "..", "EntraOps", "EntraOps.psd1");
const hasPowerShell = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", "exit 0"]).status === 0;
// Report test harnesses copy the specs without the module; the findings need both.
const canGenerateFindings = hasPowerShell && existsSync(moduleManifest);

const id = (n) => `${String(n).padStart(8, "0")}-0000-0000-0000-${String(n).padStart(12, "0")}`;
const roles = { ga: id(101), helpdesk: id(102), custom: id(103), unknown: id(104), security: id(105), pra: id(106) };
const users = { cp: id(1), mp: id(2), ua: id(3), byName: id(4), merged: id(5), mp6: id(6), mp7: id(7), unknown: id(99) };
const groups = { cp: id(201), mp: id(202), ua: id(203), approvers: id(204) };

function eamObject(objectId, upn, displayName, tierName, roleAssignments = []) {
    return { objectId, objectType: "user", objectUserPrincipalName: upn, objectDisplayName: displayName, objectAdminTierLevelName: tierName, classification: [], roleAssignments };
}

const eamData = {
    objects: [
        eamObject(users.cp, "cp.admin@contoso.com", "CP Admin", "ControlPlane", [{ roleDefinitionId: roles.ga, classification: [{ adminTierLevelName: "ControlPlane", service: "Global" }] }]),
        // Assignment evidence: the most privileged classification votes Management Plane for the Helpdesk role.
        eamObject(users.mp, "mp.admin@contoso.com", "MP Admin", "ManagementPlane", [{ roleDefinitionId: roles.helpdesk, classification: [{ adminTierLevelName: "UserAccess", service: "Users" }, { adminTierLevelName: "ManagementPlane", service: "Groups" }] }]),
        eamObject(users.ua, "ua.user@contoso.com", "UA User", "UserAccess"),
        eamObject(users.byName, "", "Approver By Name", "ManagementPlane"),
        // Two rows of one object: the most privileged tier wins.
        eamObject(users.merged, "merged@contoso.com", "Merged Admin", "UserAccess"),
        eamObject(users.merged, "merged@contoso.com", "Merged Admin", "ControlPlane"),
        eamObject(users.mp6, "mp6@contoso.com", "MP Six", "ManagementPlane"),
        eamObject(users.mp7, "mp7@contoso.com", "MP Seven", "ManagementPlane")
    ],
    roleDefinitions: [{ roleDefinitionId: roles.security, tierName: "ControlPlane", service: "Security" }]
};

const tierMap = {
    roles: [
        { sys: "EntraID", roleId: roles.ga, role: "Global Administrator", roleClass: "ControlPlane", service: "" },
        { sys: "EntraID", roleId: roles.helpdesk, role: "Helpdesk Administrator", roleClass: "UserAccess", service: "" },
        { sys: "EntraID", roleId: roles.security, role: "Security Administrator", roleClass: "ManagementPlane", service: "" },
        { sys: "Azure", roleId: roles.unknown, role: "Owner", roleClass: "ControlPlane", service: "" }
    ],
    paths: [
        { sys: "EntraID", roleId: roles.pra, roleClass: "", tier: "ControlPlane", action: "microsoft.directory/roleAssignments/allProperties/allTasks", service: "Roles" },
        { sys: "EntraID", roleId: "", roleClass: "", tier: "ManagementPlane", action: "microsoft.directory/groups/members/update", service: "Groups" }
    ]
};

function roleSetting(roleId, displayName, properties) {
    return {
        Id: roleId, DisplayName: displayName, ActivationReqMFA: true, ApprovaltoActivate: false, ActivateApprover: [],
        PermanentEligibleAssignmentisExpirationRequired: true, PermanentActiveAssignmentisExpirationRequired: true, AssignmentReqMFA: true, ...properties
    };
}

const blobs = {};
function resource(type, folder, name, properties) {
    const hash = `h${Object.keys(blobs).length + 1}`;
    blobs[hash] = { resourceType: type, displayName: name, properties };
    return { p: `${type}/${folder}/${name}.json`, h: hash };
}

const latestResources = [
    resource("microsoft.entra.rolesetting", "Global", "Global Administrator", roleSetting(roles.ga, "Global Administrator", {
        ActivationReqMFA: false, ActivateApprover: ["cp.admin@contoso.com"], PermanentEligibleAssignmentisExpirationRequired: false,
        PermanentActiveAssignmentisExpirationRequired: false, AssignmentReqMFA: false
    })),
    resource("microsoft.entra.rolesetting", "Helpdesk", "Helpdesk Administrator", roleSetting(roles.helpdesk, "Helpdesk Administrator", {
        ApprovaltoActivate: true, ActivateApprover: ["ua.user@contoso.com", "Approver By Name", "unknown@contoso.com", "Unknown Approver Group"], AuthenticationContextRequired: true, AuthenticationContextName: ""
    })),
    resource("microsoft.entra.rolesetting", "Custom", "Custom Groups Role", roleSetting(roles.custom, "", { ActivationReqMFA: false, ApprovaltoActivate: true, ActivateApprover: ["cp.admin@contoso.com"] })),
    resource("microsoft.entra.roledefinition", "Custom", "Custom Groups Role", { Id: roles.custom, DisplayName: "Custom Groups Role", RolePermissions: [{ AllowedResourceActions: ["microsoft.directory/groups/members/update"] }] }),
    resource("microsoft.entra.rolesetting", "Unknown", "Unknown Role", roleSetting(roles.unknown, "Unknown Role", { ApprovaltoActivate: true, ActivateApprover: ["cp.admin@contoso.com"], PermanentActiveAssignmentisExpirationRequired: false })),
    resource("microsoft.entra.rolesetting", "Security", "Security Administrator", roleSetting(roles.security, "Security Administrator", { ApprovaltoActivate: true, ActivateApprover: ["mp.admin@contoso.com"] })),
    resource("microsoft.entra.entitlementmanagementaccesspackagecatalog", "Tier0", "Tier0 Catalog", { Id: "cat1", DisplayName: "Tier0 Catalog" }),
    resource("microsoft.entra.entitlementmanagementaccesspackagecatalogresource", "Tier0", "CP Group", { OriginId: groups.cp, DisplayName: "CP Group", ResourceType: "AadGroup", CatalogId: "cat1" }),
    resource("microsoft.entra.entitlementmanagementaccesspackage", "Tier0", "CP Access", {
        Id: "pk1", DisplayName: "CP Access", CatalogId: "cat1",
        AccessPackageResourceRoleScopes: [{ AccessPackageResourceOriginId: groups.cp, AccessPackageResourceRoleDisplayName: "Member", AccessPackageResourceTierName: "ManagementPlane" }]
    }),
    // The snapshot misses the resource role scopes of this package: the live data restores them.
    resource("microsoft.entra.entitlementmanagementaccesspackage", "Tier1", "MP Access", { Id: "pk2", DisplayName: "MP Access", CatalogId: "cat1", AccessPackageResourceRoleScopes: [] }),
    resource("microsoft.entra.entitlementmanagementaccesspackage", "Tier2", "UA Access", {
        Id: "pk3", DisplayName: "UA Access", CatalogId: "cat1", AccessPackageResourceRoleScopes: [{ AccessPackageResourceOriginId: groups.ua, AccessPackageResourceTierName: "UserAccess" }]
    }),
    // Snapshots serialize AccessPackageId as the package display name.
    resource("microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy", "Tier0", "Self-service", {
        Id: "pol1", DisplayName: "Self-service", AccessPackageId: "CP Access",
        RequestorSettings: { ScopeType: "AllExistingDirectoryMemberUsers", AllowedRequestors: [] }, RequestApprovalSettings: { IsApprovalRequired: false }
    }),
    resource("microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy", "Tier1", "Approved", {
        Id: "pol2", DisplayName: "Approved", AccessPackageId: "pk2",
        RequestorSettings: { ScopeType: "SpecificDirectorySubjects", AllowedRequestors: [{ odataType: "#microsoft.graph.singleUser", Id: users.ua }] },
        RequestApprovalSettings: { IsApprovalRequired: true, ApprovalStages: [{ PrimaryApprovers: [{ odataType: "#microsoft.graph.singleUser", Id: users.ua }, { odataType: "#microsoft.graph.groupMembers" }] }] }
    }),
    resource("microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy", "Tier2", "UA Policy", {
        Id: "pol3", DisplayName: "UA Policy", AccessPackageId: "pk3",
        RequestorSettings: { ScopeType: "AllExistingDirectorySubjects" }, RequestApprovalSettings: { IsApprovalRequired: true, ApprovalStages: [{ PrimaryApprovers: [{ odataType: "#microsoft.graph.singleUser", Id: users.cp }] }] }
    }),
    // The group id of the only approver is in the live data only (one live approver, lower-case keys).
    resource("microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy", "Tier1", "Single live approver", {
        Id: "pol6", DisplayName: "Single live approver", AccessPackageId: "pk2",
        RequestorSettings: { ScopeType: "SpecificDirectorySubjects" },
        RequestApprovalSettings: { IsApprovalRequired: true, ApprovalStages: [{ PrimaryApprovers: [{ odataType: "#microsoft.graph.groupMembers" }] }] }
    }),
    // An unresolved approver (twice, de-duplicated by label) is not compared; the resolved User Access approver is.
    resource("microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy", "Tier0", "User Access approver", {
        Id: "pol4", DisplayName: "User Access approver", AccessPackageId: "pk1",
        RequestorSettings: { ScopeType: "SpecificDirectorySubjects" },
        RequestApprovalSettings: { IsApprovalRequired: true, ApprovalStages: [{ PrimaryApprovers: [{ odataType: "#microsoft.graph.singleUser", Id: users.unknown }, { odataType: "#microsoft.graph.singleUser", Id: users.unknown }, { odataType: "#microsoft.graph.singleUser", Id: users.ua }] }] }
    })
];
const olderResources = [
    resource("microsoft.entra.rolesetting", "Global", "Global Administrator", roleSetting(roles.ga, "Global Administrator", { ApprovaltoActivate: false }))
];

const configurationAnalyzerData = {
    generatedAt: "2026-10-27T08:00:00.0000000Z",
    snapshots: [
        { commitSha: "aaaaaaaa", commitDate: "2026-10-01T10:00:00.0000000+00:00", subject: "older", hasDetail: true, resources: olderResources },
        { commitSha: "bbbbbbbb", commitDate: "2026-10-10T10:00:00.0000000+00:00", subject: "without detail", hasDetail: false, resources: olderResources },
        { commitSha: "cccccccc", commitDate: "2026-10-20T10:00:00.0000000+00:00", subject: "latest", hasDetail: true, resources: latestResources }
    ],
    blobs,
    resolvedGroupTiers: { [groups.cp]: { tierName: "ControlPlane", displayName: "CP Group", totalMembers: 1, privilegedMemberCount: 1, members: [{ id: users.cp, displayName: "CP Admin", tierName: "ControlPlane" }] } }
};

const assignment = (objectId, assignmentPolicyId, state = "delivered") => ({ accessPackageId: "pk1", assignmentPolicyId, state, target: { objectId, displayName: "", principalName: "" } });
const accessPackageData = {
    policyRequestorApprovers: {
        pol2: { accessPackageId: "pk2", scopeType: "SpecificDirectorySubjects", requestors: [], approvers: [{}, { Id: groups.approvers, DisplayName: "Approvers" }] },
        pol6: { accessPackageId: "pk2", scopeType: "SpecificDirectorySubjects", requestors: [], approvers: [{ "@odata.type": "#microsoft.graph.groupMembers", id: groups.approvers, description: "Approvers" }] }
    },
    packages: { pk2: { displayName: "MP Access", catalogId: "cat1", catalogName: "Tier0 Catalog", targets: [{ originId: groups.mp, displayName: "MP Group", role: "Member", originSystem: "AadGroup", resourceType: "Group", tierName: "ManagementPlane" }] } },
    resolvedGroupTiers: { [groups.approvers]: { tierName: "UserAccess", displayName: "Approvers", totalMembers: 2, privilegedMemberCount: 0, members: [] } },
    assignments: [
        assignment(users.cp, "pol4"), assignment(users.mp, "pol4"), assignment(users.byName, "pol4"), assignment(users.merged, "pol4"),
        assignment(users.mp6, "pol4"), assignment(users.mp7, "pol4"),
        assignment(users.cp, "pol4", "expired"), assignment(users.cp, null)
    ],
    // Access drift (Access Guardian) of the Control Plane group of "CP Access".
    accessDrift: {
        status: "collected",
        reason: "",
        resources: [{ id: "d1", resourceId: groups.cp, resourceName: "CP Group", resourceType: "group", catalogId: "cat1", catalogName: "Tier0 Catalog", total: 2, unauthorized: 1, missing: 1, createdDateTime: "2026-10-26T03:15:42Z", details: [] }]
    }
};

let fixtureRoot;
const urls = {};

async function copyReports(target) {
    for (const folder of ["shared", "ConfigurationAnalyzer", "PimRequestFlow", "AccessPackageFlow"]) {
        const source = join(reportsSourceDir, folder);
        await cp(source, join(target, folder), {
            recursive: true,
            filter: (path) => {
                const parts = relative(source, path).split(sep);
                return parts[0] !== "data" && !path.endsWith(".spec.mjs");
            }
        });
    }
    const write = async (file, variable, data) => {
        await mkdir(join(target, file, ".."), { recursive: true });
        await writeFile(join(target, file), `window.${variable} = ${JSON.stringify(data)};\n`, "utf8");
    };
    await write("ConfigurationAnalyzer/data/configuration-analyzer-data.js", "ENTRAOPS_CONFIGANALYZER_DATA", configurationAnalyzerData);
    await write("ClassificationExplorer/data/tier-map.js", "EOCE_TIER_MAP", tierMap);
    await write("EamDashboard/data/eam-dashboard-data.js", "ENTRAOPS_EAM_DATA", eamData);
    await write("AccessPackageFlow/data/access-package-assignments-data.js", "ENTRAOPS_ACCESSPACKAGE_ASSIGNMENTS", accessPackageData);
}

test.beforeAll(async () => {
    test.skip(!canGenerateFindings, "Needs PowerShell and the EntraOps module next to the Reports folder.");
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-flow-findings-"));
    for (const variant of ["missing", "powershell"]) await copyReports(join(fixtureRoot, variant));

    const script = `$ErrorActionPreference = 'Stop'; Import-Module '${moduleManifest.replace(/'/g, "''")}' -Force -WarningAction SilentlyContinue; ` +
        `New-EntraOpsReportFindingData -ReportPath '${join(fixtureRoot, "powershell").replace(/'/g, "''")}' | Out-Null`;
    const result = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], { env: { ...process.env, ENTRAOPS_NOWELCOME: "1" }, encoding: "utf8" });
    expect(result.status, result.stderr || result.stdout).toBe(0);
    for (const variant of ["missing", "powershell"]) {
        urls[variant] = {
            pim: pathToFileURL(join(fixtureRoot, variant, "PimRequestFlow", "index.html")).href,
            accessPackage: pathToFileURL(join(fixtureRoot, variant, "AccessPackageFlow", "index.html")).href
        };
    }
});

test.afterAll(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

const latestKey = "cccccccc|2026-10-20T10:00:00.0000000+00:00";
const reports = [
    { name: "PIM Request Flow", key: "pim", app: "PimRequestFlow", file: "pim-request-flow-findings.js", container: "pimFlagsBody", stat: "pimStatFlagged", variable: "ENTRAOPS_PIM_REQUEST_FLOW_FINDINGS", ids: ["noMfaActivation", "noApprovalActivation", "approverNotEnforced", "approverLowerTier", "approverUnclassified", "authContextMissing", "permanentEligible", "permanentActive", "noMfaActiveAssign"] },
    { name: "Access Package Flow", key: "accessPackage", app: "AccessPackageFlow", file: "access-package-flow-findings.js", container: "apFlagsBody", stat: "apStatFlagged", variable: "ENTRAOPS_ACCESS_PACKAGE_FLOW_FINDINGS", ids: ["noApproval", "broadRequestor", "approverLowerTier", "assignedMorePrivileged", "unauthorizedAccess", "missingAccess"] }
];
const findingsFile = (report) => join(fixtureRoot, "powershell", report.app, "data", report.file);
async function readFindings(report) {
    const content = await readFile(findingsFile(report), "utf8");
    return JSON.parse(content.slice(content.indexOf("=") + 1, content.lastIndexOf(";")));
}
async function writeFindings(report, findings) {
    await writeFile(findingsFile(report), `window.${report.variable} = ${JSON.stringify(findings)};\n`, "utf8");
}

// Flag texts are shown with the display names of the tiers ("ControlPlane" -> "Control Plane").
const TIER_TEXT = { ControlPlane: "Control Plane", ManagementPlane: "Management Plane", WorkloadPlane: "Workload Plane", UserAccess: "User Access" };
const display = (text) => String(text).replace(/\b(ControlPlane|ManagementPlane|WorkloadPlane|UserAccess)\b/g, (tier) => TIER_TEXT[tier]);

// Every rendered risk flag as "<flowId>|<flagId>: <text>" (collapsed groups are rendered, only hidden).
async function renderedFlags(page, url, report) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(url);
    await expect(page.locator(`#${report.container} [data-review-finding]`).first()).toBeAttached();
    // Open flags only: a flag accepted by a finding exception has no review status.
    const flags = await page.locator(`#${report.container} .ca-gap-row:not(.flow-flag-accepted)`).evaluateAll((rows) => rows.map((row) => {
        const control = row.querySelector("[data-review-finding]");
        const detail = row.querySelector(".ca-gap-detail");
        return decodeURIComponent(control.getAttribute("data-review-finding")) + ": " + detail.textContent.split(" · ")[0];
    }));
    expect(pageErrors).toEqual([]);
    return flags.sort();
}

async function expectNotEvaluated(page, url, report, message) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(url);
    // One notice at the top of the page (shared/flow-findings.js); the risk flag list points to it.
    await expect(page.locator("[data-risk-flag-notice]")).toHaveCount(1);
    await expect(page.locator("[data-risk-flag-notice]")).toBeVisible();
    await expect(page.locator("[data-risk-flag-notice]")).toContainText(message);
    await expect(page.locator(`#${report.container}`)).toContainText("See the notice at the top of the page.");
    await expect(page.locator(`#${report.container} [data-review-finding]`)).toHaveCount(0);
    await expect(page.locator(`#${report.stat}`)).toHaveText("–");
    expect(pageErrors).toEqual([]);
}

for (const report of reports) {
    test(`${report.name} shows the risk flags of the PowerShell findings file`, async ({ page }) => {
        const findings = await readFindings(report);
        const latest = findings.snapshots[latestKey];
        expect(latest).toBeTruthy();
        const expected = Object.keys(latest.flags).flatMap((flowId) => latest.flags[flowId].map((flag) => `${flowId}|${flag.id}: ${display(flag.text)}`)).sort();

        expect(await renderedFlags(page, urls.powershell[report.key], report)).toEqual(expected);
        // The fixture triggers every risk flag of the report.
        for (const flagId of report.ids) {
            expect(expected.some((flag) => flag.split(": ")[0].endsWith(`|${flagId}`)), flagId).toBe(true);
        }
    });

    test(`${report.name} shows a notice instead of risk flags without the findings file`, async ({ page }) => {
        await expectNotEvaluated(page, urls.missing[report.key], report, "were not evaluated for this data");
    });
}

test("PIM Request Flow shows the role tiers and approvers of the findings file", async ({ page }) => {
    const report = reports[0];
    await page.goto(urls.powershell.pim);
    // Global Administrator, Helpdesk, Custom (role action) and Security are classified; the Azure role id is not.
    await expect(page.locator("#pimStatTierData")).toHaveText("4 of 5 role(s) classified");
    await page.goto(`${urls.powershell.pim}#flow=${encodeURIComponent(`${roles.helpdesk}|activation`)}`);
    await expect(page.locator("#pimFlowDetail")).toContainText("UA User (ua.user@contoso.com)");
    await expect(page.locator("#pimFlowDetail")).not.toContainText("Tier not evaluated");
    await expect(page.locator("[data-risk-flag-notice]")).toBeHidden();

    const original = await readFindings(report);
    const findings = structuredClone(original);
    delete findings.snapshots[latestKey].roles[roles.ga].tier;
    await writeFindings(report, findings);
    try {
        await page.goto(urls.powershell.pim);
        await expect(page.locator("#pimStatTierData")).toHaveText("3 of 5 role(s) classified");
    } finally {
        await writeFindings(report, original);
    }
    await page.goto(urls.missing.pim);
    await expect(page.locator("#pimStatTierData")).toHaveText("not evaluated");
    // Without findings the detail card claims neither "no risk" (green border) nor "Unclassified".
    await page.goto(`${urls.missing.pim}#flow=${encodeURIComponent(`${roles.helpdesk}|activation`)}`);
    const detail = page.locator("#pimFlowDetail");
    await expect(detail).toContainText("Tier not evaluated");
    await expect(detail).not.toContainText("Unclassified");
    await expect(detail.locator(".card")).toHaveAttribute("style", /border-left:4px solid var\(--neutral-stroke-strong\)/);
});

test("Access Package Flow shows the tiers of the findings file", async ({ page }) => {
    // The assigned principal and the target resource (a group resolved via its members) of pol4.
    await page.goto(`${urls.powershell.accessPackage}#flow=pol4`);
    const detail = page.locator("#apFlowDetail");
    await expect(detail).toContainText("CP Group (Member)");
    await expect(detail.locator(".status-chip", { hasText: "Control Plane" }).first()).toBeVisible();
    await expect(detail).toContainText("CP Admin");

    await page.goto(`${urls.missing.accessPackage}#flow=pol4`);
    await expect(page.locator("#apFlowDetail")).toContainText("CP Group (Member)");
    await expect(page.locator("#apFlowDetail .status-chip", { hasText: "Control Plane" })).toHaveCount(0);
    await expect(page.locator("#apFlowDetail")).toContainText("Tier not evaluated");
    await expect(page.locator("#apFlowDetail .card").first()).toHaveAttribute("style", /border-left:4px solid var\(--neutral-stroke-strong\)/);
});

test("PIM Request Flow shows the flags of the findings file and ignores findings of other report data", async ({ page }) => {
    const report = reports[0];
    const original = await readFindings(report);
    const findings = structuredClone(original);
    findings.snapshots[latestKey].flags[`${roles.ga}|activation`] = [{ id: "noMfaActivation", severity: "fail", text: "Flag from the PowerShell findings." }];
    await writeFindings(report, findings);
    try {
        const flags = await renderedFlags(page, urls.powershell.pim, report);
        expect(flags).toContain(`${roles.ga}|activation|noMfaActivation: Flag from the PowerShell findings.`);
        expect(flags.some((flag) => flag.startsWith(`${roles.ga}|activation|noApprovalActivation`))).toBe(false);

        // Findings evaluated from other datasets (here: an older Configuration Analyzer data) are not shown.
        expect(findings.sources).toEqual({ configurationAnalyzer: configurationAnalyzerData.generatedAt, eam: null, tierMap: null });
        findings.sources.configurationAnalyzer = "2026-10-01T00:00:00.0000000Z";
        await writeFindings(report, findings);
        await expectNotEvaluated(page, urls.powershell.pim, report, "evaluated from other report data");
    } finally {
        await writeFindings(report, original);
    }
});

test("Access Package Flow shows a notice for findings of other report data or another EntraOps version", async ({ page }) => {
    const report = reports[1];
    const original = await readFindings(report);
    const findings = structuredClone(original);
    findings.sources.accessPackage = "2026-10-01T00:00:00.0000000Z";
    await writeFindings(report, findings);
    try {
        await expectNotEvaluated(page, urls.powershell.accessPackage, report, "evaluated from other report data");
        // Files of an EntraOps version with another file format (risk flags only, no tiers).
        await writeFindings(report, { ...original, schemaVersion: undefined });
        await expectNotEvaluated(page, urls.powershell.accessPackage, report, "written by another EntraOps version");
    } finally {
        await writeFindings(report, original);
    }
});

// Captures the rows the export buttons write (EntraOpsReportUtils.exportRows) instead of downloading them.
async function captureExports(page) {
    await page.evaluate(() => {
        window.__exports = [];
        window.EntraOpsReportUtils.exportRows = (name, rows) => window.__exports.push({ name, rows });
    });
}

test("flow reports show accepted flags muted with their exception, without counting them", async ({ page }) => {
    for (const report of reports) {
        const original = await readFindings(report);
        const findings = structuredClone(original);
        const latest = findings.snapshots[latestKey];
        const flowId = Object.keys(latest.flags)[0];
        const [accepted, ...open] = latest.flags[flowId];
        latest.accepted = { [flowId]: [{ ...accepted, ruleId: accepted.ruleId || "", state: "RiskAccepted", expiresOn: "2027-01-31", justification: "Migration" }] };
        if (open.length) latest.flags[flowId] = open; else delete latest.flags[flowId];
        await writeFindings(report, findings);
        try {
            await page.goto(urls.powershell[report.key]);
            const acceptedRow = page.locator(`#${report.container} .ca-gap-row.flow-flag-accepted`);
            await expect(acceptedRow).toHaveCount(1);
            await expect(acceptedRow).toContainText("Risk accepted until 2027-01-31");
            // No review status on an accepted flag, and the open flags are still listed.
            await expect(acceptedRow.locator("[data-review-finding]")).toHaveCount(0);
            const openFlags = await renderedFlags(page, urls.powershell[report.key], report);
            expect(openFlags.some((flag) => flag.startsWith(`${flowId}|${accepted.id}:`))).toBe(false);
            // The export lists the accepted flag with its exception.
            await captureExports(page);
            await page.click(report.key === "pim" ? "#pimExportRiskFlags" : "#apExportRiskFlags");
            const rows = await page.evaluate(() => window.__exports[0].rows);
            expect(rows.filter((row) => row.exception === "Risk accepted until 2027-01-31")).toHaveLength(1);
        } finally {
            await writeFindings(report, original);
        }
    }
});

test("a flag whose exception has expired is an open flag again, with a note to evaluate the findings again", async ({ page }) => {
    for (const report of reports) {
        const original = await readFindings(report);
        const findings = structuredClone(original);
        const latest = findings.snapshots[latestKey];
        const flowId = Object.keys(latest.flags)[0];
        const [accepted, ...open] = latest.flags[flowId];
        latest.accepted = { [flowId]: [{ ...accepted, ruleId: accepted.ruleId || "", state: "RiskAccepted", expiresOn: "2020-01-31", justification: "Migration" }] };
        if (open.length) latest.flags[flowId] = open; else delete latest.flags[flowId];
        await writeFindings(report, findings);
        try {
            await page.goto(urls.powershell[report.key]);
            // Not muted and not labelled as accepted: the exception expired after the evaluation.
            await expect(page.locator(`#${report.container} [data-review-finding]`).first()).toBeAttached();
            await expect(page.locator(`#${report.container} .ca-gap-row.flow-flag-accepted`)).toHaveCount(0);
            await expect(page.locator(`#${report.container}`)).not.toContainText("Risk accepted until");
            const expiredRow = page.locator(`#${report.container} .ca-gap-row`).filter({ has: page.locator(".flow-exception-expired") });
            await expect(expiredRow).toHaveCount(1);
            await expect(expiredRow.locator(".flow-exception-expired")).toHaveText("Exception expired 2020-01-31");
            await expect(expiredRow).toContainText("run New-EntraOpsReportingData to evaluate the findings again");
            // It counts as an open flag again: with a review status, and in the list of the open flags.
            await expect(expiredRow.locator("[data-review-finding]")).toHaveCount(1);
            const openFlags = await renderedFlags(page, urls.powershell[report.key], report);
            expect(openFlags.some((flag) => flag.startsWith(`${flowId}|${accepted.id}:`))).toBe(true);
            await captureExports(page);
            await page.click(report.key === "pim" ? "#pimExportRiskFlags" : "#apExportRiskFlags");
            const rows = await page.evaluate(() => window.__exports[0].rows);
            expect(rows.filter((row) => row.exception === "Exception expired 2020-01-31")).toHaveLength(1);
            expect(rows.filter((row) => /^Risk accepted/.test(row.exception))).toHaveLength(0);
        } finally {
            await writeFindings(report, original);
        }
    }
});

test("Access Package Flow groups the risk flags by a catalog named like a member of Object.prototype", async ({ page }) => {
    const dataFile = join(fixtureRoot, "powershell", "ConfigurationAnalyzer", "data", "configuration-analyzer-data.js");
    const original = await readFile(dataFile, "utf8");
    const data = structuredClone(configurationAnalyzerData);
    Object.values(data.blobs).filter((blob) => blob.resourceType === "microsoft.entra.entitlementmanagementaccesspackagecatalog").forEach((blob) => { blob.properties.DisplayName = "constructor"; });
    await writeFile(dataFile, `window.ENTRAOPS_CONFIGANALYZER_DATA = ${JSON.stringify(data)};\n`, "utf8");
    try {
        const pageErrors = [];
        page.on("pageerror", (error) => pageErrors.push(error.message));
        await page.goto(urls.powershell.accessPackage);
        await expect(page.locator("#apFlagsBody [data-review-finding]").first()).toBeAttached();
        await page.selectOption("#apFlagGroup", "catalog");
        await expect(page.locator("#apFlagsBody .eo-group-title").filter({ hasText: /^constructor$/ })).toHaveCount(1);
        await expect(page.locator('#apFlagsBody .eo-group[data-group="catalog|constructor"] .ca-gap-row').first()).toBeAttached();
        expect(pageErrors).toEqual([]);
    } finally {
        await writeFile(dataFile, original, "utf8");
    }
});

test("flag filters and flag rows name the check by its rule and link to the Findings view", async ({ page }) => {
    const report = reports[0];
    const original = await readFindings(report);
    const findings = structuredClone(original);
    findings.rules = [{ id: "EO.3006", key: "noMfaActivation", title: "Activation of a privileged role without MFA", status: "Failed" }];
    await writeFindings(report, findings);
    try {
        await page.goto(urls.powershell.pim);
        await expect(page.locator('#pimFltFlag option[value="noMfaActivation"]')).toHaveText("EO.3006 · Activation of a privileged role without MFA");
        const link = page.locator('#pimFlagsBody .flow-rule-link', { hasText: "EO.3006" }).first();
        await expect(link).toHaveAttribute("href", "../PrivilegedAssets/index.html?view=findings#rule=EO.3006");
        // Without a rule, the option is the first sentence of the flag text (never cut inside a name).
        await expect(page.locator('#pimFltFlag option[value="noApprovalActivation"]')).not.toHaveText("");
    } finally {
        await writeFindings(report, original);
    }
});

test("flow reports without evaluated findings hide the tier pills and export 'not evaluated'", async ({ page }) => {
    await page.goto(urls.missing.pim);
    await expect(page.locator("#pimTierRow")).toBeHidden();
    await expect(page.locator('[data-pim-metric="noMfaActivation"]')).toBeDisabled();
    await expect(page.locator('[data-pim-metric="anyRisk"]')).toBeDisabled();
    await captureExports(page);
    await page.click("#pimExportFiltered");
    const pimRows = await page.evaluate(() => window.__exports[0].rows);
    expect(pimRows.length).toBeGreaterThan(0);
    expect(pimRows.every((row) => row.accessLevel === "not evaluated" && row.riskFlags === "not evaluated")).toBe(true);

    await page.goto(urls.missing.accessPackage);
    await expect(page.locator("#apRequestorTierRow")).toBeHidden();
    await expect(page.locator('[data-ap-metric="anyRisk"]')).toBeDisabled();
    await captureExports(page);
    await page.click("#apExportFiltered");
    const apRows = await page.evaluate(() => window.__exports[0].rows);
    expect(apRows.length).toBeGreaterThan(0);
    expect(apRows.every((row) => row.riskFlags === "not evaluated")).toBe(true);
});

test("the notice of stale findings names the dataset and both times, and lists excluded checks", async ({ page }) => {
    const report = reports[0];
    const original = await readFindings(report);
    const findings = structuredClone(original);
    findings.sources.configurationAnalyzer = "2026-10-01T00:00:00.0000000Z";
    findings.rules = [{ id: "EO.3007", key: "noApprovalActivation", title: "Activation without approval", status: "Excluded" }];
    await writeFindings(report, findings);
    try {
        await page.goto(urls.powershell.pim);
        const notice = page.locator("#pimFindingsNotice");
        await expect(notice).toContainText("Configuration Analyzer data (evaluated: 2026-10-01 00:00 UTC, shown:");
        await expect(notice).toContainText("EO.3007 Activation without approval");
    } finally {
        await writeFindings(report, original);
    }
    // Evaluated findings with an excluded rule: the tile says "excluded" instead of 0.
    const excluded = structuredClone(original);
    excluded.rules = (excluded.rules || []).filter((rule) => rule.key !== "noApprovalActivation").concat([{ id: "EO.3007", key: "noApprovalActivation", title: "Activation without approval", status: "Excluded" }]);
    await writeFindings(report, excluded);
    try {
        await page.goto(urls.powershell.pim);
        await expect(page.locator("#pimStatNoApproval")).toHaveText("excluded");
        await expect(page.locator("#pimFindingsNotice")).toContainText("Excluded checks");
    } finally {
        await writeFindings(report, original);
    }
});

test("a #flow= deep link clears the filters that hide the path and matches the ID case-insensitively", async ({ page }) => {
    await page.goto(urls.powershell.pim);
    // Hide the Global Administrator activation path behind a filter, then follow a link with an upper-case ID.
    await page.locator('#pimApprovalPills .eo-pill[data-value="required"]').click();
    await page.evaluate((hash) => { location.hash = hash; }, `#flow=${encodeURIComponent(`${roles.ga}|activation`.toUpperCase())}`);
    await expect(page.locator("#pimFlowDetail")).toBeVisible();
    await expect(page.locator("#pimFlowDetail")).toContainText("Global Administrator");
    await expect(page.locator('#pimApprovalPills .eo-pill.active')).toHaveAttribute("data-value", "");
    await expect(page.locator("#pimFilterSummary")).not.toContainText("0 of");
});
