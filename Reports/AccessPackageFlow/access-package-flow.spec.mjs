import { expect, test } from "@playwright/test";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Filters of the Access Package Flow: the search bar (search, snapshot, catalog and risk flag dropdowns, reset), the
// facet pills (approval, expiration, requestor and group member access level, target resource type) with the number
// of matching assignment policies, and the collapsible groups of the risk flag list. Synthetic data only.

const reportsSourceDir = fileURLToPath(new URL("..", import.meta.url));
const generatedAt = "2026-01-01T00:00:00Z";
const id = (n) => `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const groups = { tier0: id(201), helpdesk: id(202), requestors: id(203) };
const apps = { hr: id(301), subscription: id(302) };
const users = { admin: id(1), approver: id(2), helpdesk: id(3), user: id(4) };

const blobs = {};
function resource(type, folder, name, properties) {
    const hash = `h${Object.keys(blobs).length + 1}`;
    blobs[hash] = { resourceType: type, displayName: name, properties };
    return { p: `microsoft.entra.${type}/${folder}/${name}.json`, h: hash };
}
const catalog = (catalogId, name) => resource("entitlementmanagementaccesspackagecatalog", name, name, { Id: catalogId, DisplayName: name });
const catalogResource = (originId, name, resourceType, catalogId) =>
    resource("entitlementmanagementaccesspackagecatalogresource", catalogId, name, { OriginId: originId, DisplayName: name, ResourceType: resourceType, CatalogId: catalogId });
const accessPackage = (packageId, name, catalogId, targets) => resource("entitlementmanagementaccesspackage", catalogId, name, {
    Id: packageId, DisplayName: name, CatalogId: catalogId,
    AccessPackageResourceRoleScopes: targets.map(([originId, role]) => ({ AccessPackageResourceOriginId: originId, AccessPackageResourceRoleDisplayName: role }))
});
const policy = (policyId, name, packageId, requestorSettings, approvalSettings, durationInDays) =>
    resource("entitlementmanagementaccesspackageassignmentpolicy", packageId, name, {
        Id: policyId, DisplayName: name, AccessPackageId: packageId, RequestorSettings: requestorSettings, RequestApprovalSettings: approvalSettings, DurationInDays: durationInDays
    });
const singleUser = (userId) => ({ odataType: "#microsoft.graph.singleUser", Id: userId });

// Four assignment policies: two without approval (pol1, pol4), two with a fixed expiration (pol2, pol3).
// Targets: groups (pk1, pk2), an application (API permissions) and an Azure subscription (Azure RBAC) for pk3.
const latestResources = [
    catalog("cat1", "Contoso Tier0 Catalog"),
    catalog("cat2", "Contoso Apps Catalog"),
    catalogResource(groups.tier0, "Contoso Tier0 Admins", "AadGroup", "cat1"),
    catalogResource(groups.helpdesk, "Contoso Helpdesk", "AadGroup", "cat1"),
    catalogResource(apps.hr, "Contoso HR App", "AadApplication", "cat2"),
    catalogResource(apps.subscription, "Contoso Subscription", "Subscription", "cat2"),
    accessPackage("pk1", "Tier0 Admin Access", "cat1", [[groups.tier0, "Member"]]),
    accessPackage("pk2", "Helpdesk Access", "cat1", [[groups.helpdesk, "Member"]]),
    accessPackage("pk3", "HR App Access", "cat2", [[apps.hr, "User"], [apps.subscription, "Reader"]]),
    policy("pol1", "Tier0 self-service", "pk1", { ScopeType: "AllExistingDirectoryMemberUsers", AllowedRequestors: [] }, { IsApprovalRequired: false }, 0),
    policy("pol2", "Tier0 approved", "pk1", { ScopeType: "SpecificDirectorySubjects", AllowedRequestors: [singleUser(users.admin)] },
        { IsApprovalRequired: true, ApprovalStages: [{ PrimaryApprovers: [singleUser(users.approver)] }] }, 30),
    policy("pol3", "Helpdesk requests", "pk2", { ScopeType: "SpecificDirectorySubjects", AllowedRequestors: [{ odataType: "#microsoft.graph.groupMembers", Id: groups.requestors }] },
        { IsApprovalRequired: true, ApprovalStages: [{ PrimaryApprovers: [singleUser(users.approver)] }] }, 90),
    policy("pol4", "HR App requests", "pk3", { ScopeType: "AllExistingDirectorySubjects" }, { IsApprovalRequired: false }, null)
];
const olderResources = latestResources.filter((item) => !/HR App|Contoso Apps|Contoso Subscription/.test(item.p));

const configurationAnalyzerData = {
    generatedAt,
    snapshots: [
        { commitSha: "aaaaaaaa", commitDate: "2026-01-01T08:00:00Z", subject: "older", hasDetail: true, resources: olderResources },
        { commitSha: "bbbbbbbb", commitDate: "2026-01-02T08:00:00Z", subject: "latest", hasDetail: true, resources: latestResources }
    ],
    blobs,
    resolvedGroupTiers: {
        [groups.requestors]: {
            tierName: "ManagementPlane", displayName: "Contoso Helpdesk Requestors", totalMembers: 2, privilegedMemberCount: 1,
            members: [{ id: users.helpdesk, displayName: "Contoso Helpdesk Agent", tierName: "ManagementPlane" }, { id: users.user, displayName: "Contoso User", tierName: "UserAccess" }]
        }
    }
};

const latestKey = "bbbbbbbb|2026-01-02T08:00:00Z";
const approver = { id: users.approver, label: "User: Contoso Approver", tier: "UserAccess", resolved: true, source: "direct" };
const findings = {
    schemaVersion: 2,
    sources: { configurationAnalyzer: generatedAt, eam: null, accessPackage: null },
    snapshots: {
        [latestKey]: {
            flags: {
                pol1: [
                    { id: "noApproval", severity: "fail", text: "Control Plane resource can be requested without approval." },
                    { id: "broadRequestor", severity: "fail", text: "Any directory member can request a Control Plane resource." }
                ],
                pol3: [{ id: "approverLowerTier", severity: "warn", text: "The approver is classified at a lower tier than the resource." }]
            },
            packages: {
                pk1: { targets: [{ tier: "ControlPlane", source: "direct" }] },
                pk2: { targets: [{ tier: "ManagementPlane", source: "direct" }] },
                pk3: { targets: [{ tier: "UserAccess", source: "direct" }, { tier: "UserAccess", source: "direct" }] }
            },
            flows: {
                pol1: { requestors: [{ scopeType: "AllExistingDirectoryMemberUsers", tier: "UserAccess", source: "broadScope" }], approvers: [], assigned: [] },
                pol2: { requestors: [{ id: users.admin, label: "User: Contoso Admin", tier: "ControlPlane", resolved: true, source: "direct" }], approvers: [approver], assigned: [], approvalTier: "UserAccess" },
                pol3: { requestors: [{ id: groups.requestors, label: "Members of: Contoso Helpdesk Requestors", tier: "ManagementPlane", resolved: true, source: "groupMembership", groupId: groups.requestors }], approvers: [approver], assigned: [] },
                pol4: { requestors: [{ scopeType: "AllExistingDirectorySubjects" }], approvers: [], assigned: [] }
            }
        }
    }
};

let fixtureRoot;
let appUrl;
const extraFixtureRoots = [];

// Copies the report with the given findings into root and returns the URL of the page.
async function buildFixture(root, findingsData) {
    const reportsRoot = join(root, "Reports");
    for (const folder of ["shared", "ConfigurationAnalyzer", "AccessPackageFlow"]) {
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
    await write("AccessPackageFlow/data/access-package-flow-findings.js", "ENTRAOPS_ACCESS_PACKAGE_FLOW_FINDINGS", findingsData);
    return pathToFileURL(join(reportsRoot, "AccessPackageFlow", "index.html")).href;
}

test.beforeAll(async () => {
    fixtureRoot = await mkdtemp(join(tmpdir(), "entraops-access-package-flow-"));
    appUrl = await buildFixture(fixtureRoot, findings);
});

test.afterAll(async () => {
    for (const root of [fixtureRoot, ...extraFixtureRoots]) {
        if (root) await rm(root, { recursive: true, force: true });
    }
});

async function openApp(page, hash = "", url = appUrl) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(url);
    await page.evaluate(() => localStorage.clear());
    await page.goto(url + hash);
    await page.reload();
    await expect(page.locator("#apFilterSummary")).toContainText("of 4 policy path(s) shown");
    return pageErrors;
}

// The pills of a facet as "label count" (disabled pills marked with "-", the active one with "*").
async function pills(page, id) {
    return page.locator(`#${id} .eo-pill`).evaluateAll((buttons) => buttons.map((button) =>
        (button.classList.contains("active") ? "*" : "") + (button.disabled ? "-" : "") +
        button.querySelector("span:not(.eo-pill-count):not(.eo-tier-dot)").textContent + " " + button.querySelector(".eo-pill-count").textContent));
}

const summary = (page) => page.locator("#apFilterSummary");
const pill = (page, facetId, text) => page.locator(`#${facetId} .eo-pill`, { hasText: text });

test("Access Package Flow shows the facet pills with the number of matching policies", async ({ page }) => {
    const pageErrors = await openApp(page);
    await expect(summary(page)).toHaveText(" · 4 of 4 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["*All 4", "Approval required 2", "No approval required 2"]);
    expect(await pills(page, "apExpirationPills")).toEqual(["*All 4", "No expiration 2", "Fixed expiration 2"]);
    expect(await pills(page, "apRequestorTierPills")).toEqual(["*All 4", "Control Plane 1", "Management Plane 1", "User Access 1", "Unclassified 1"]);
    expect(await pills(page, "apMemberTierPills")).toEqual(["*All 4", "-Control Plane 0", "Management Plane 1", "User Access 1"]);
    expect(await pills(page, "apTargetTypePills")).toEqual(["*All 4", "Groups 3", "Azure RBAC 1", "API permissions 1", "-Directory roles 0", "-Other 0"]);
    await expect(page.locator("#apRequestorTierPills .eo-pill-tier.eo-tier-unclassified")).toHaveAttribute("title", "Unclassified / unresolved");
    // The old dropdowns are gone; the dropdowns with many values sit in the search bar.
    await expect(page.locator("#apFltApproval, #apFltExpiration, #apFltRequestorTier, #apFltMemberTier, #apFltTargetType")).toHaveCount(0);
    await expect(page.locator(".eo-searchbar .eo-select #apSnapshot, .eo-searchbar .eo-select #apFltCatalog, .eo-searchbar .eo-select #apFltFlag")).toHaveCount(3);
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow filters by a pill, updates the counts of the other facets and resets on a second click", async ({ page }) => {
    const pageErrors = await openApp(page);
    await pill(page, "apApprovalPills", "No approval required").click();
    await expect(summary(page)).toHaveText(" · 2 of 4 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["All 4", "Approval required 2", "*No approval required 2"]);
    expect(await pills(page, "apRequestorTierPills")).toEqual(["*All 2", "-Control Plane 0", "-Management Plane 0", "User Access 1", "Unclassified 1"]);
    expect(await pills(page, "apExpirationPills")).toEqual(["*All 2", "No expiration 2", "-Fixed expiration 0"]);
    expect(await pills(page, "apTargetTypePills")).toEqual(["*All 2", "Groups 1", "Azure RBAC 1", "API permissions 1", "-Directory roles 0", "-Other 0"]);

    // A target type: the policies granting it, and only its targets in the flow.
    await pill(page, "apTargetTypePills", "Azure RBAC").click();
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["All 1", "-Approval required 0", "*No approval required 1"]);
    await expect(page.locator("#apSankey")).toContainText("Contoso Subscription (Reader)");
    await expect(page.locator("#apSankey")).not.toContainText("Contoso HR App (User)");

    await pill(page, "apTargetTypePills", "Azure RBAC").click();
    await pill(page, "apApprovalPills", "No approval required").click();
    await expect(summary(page)).toHaveText(" · 4 of 4 policy path(s) shown");
    expect(await pills(page, "apTargetTypePills")).toEqual(["*All 4", "Groups 3", "Azure RBAC 1", "API permissions 1", "-Directory roles 0", "-Other 0"]);

    // Group member access level, with the keyboard.
    await pill(page, "apMemberTierPills", "User Access").focus();
    await page.keyboard.press("Enter");
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    expect(await pills(page, "apRequestorTierPills")).toEqual(["*All 1", "-Control Plane 0", "Management Plane 1", "-User Access 0", "-Unclassified 0"]);
    await page.keyboard.press("Enter");
    await expect(summary(page)).toHaveText(" · 4 of 4 policy path(s) shown");

    await pill(page, "apRequestorTierPills", "Control Plane").click();
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    expect(await pills(page, "apExpirationPills")).toEqual(["*All 1", "-No expiration 0", "Fixed expiration 1"]);
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow switches the columns of the flow, keeping at least two", async ({ page }) => {
    const pageErrors = await openApp(page);
    const column = (text) => page.locator("#apFacets #apColToggles .eo-pill-toggle", { hasText: text });
    await expect(page.locator("#apColToggles .eo-pill-toggle.active")).toHaveCount(4);
    await expect(page.locator("#apSankey")).toContainText("ACCESS");

    await column("Access package").click();
    await expect(column("Access package")).toHaveAttribute("aria-pressed", "false");
    await expect(column("Access package")).toBeFocused();
    await expect(page.locator("#apSankey")).not.toContainText("Tier0 Admin Access");
    await column("Requestor scope").click();
    await expect(page.locator("#apColToggles .eo-pill-toggle.active")).toHaveCount(2);
    // At least two columns stay.
    await column("Target resource role").click();
    await expect(column("Target resource role")).toHaveAttribute("aria-pressed", "true");
    await column("Access package").focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#apSankey")).toContainText("Tier0 Admin Access");
    await expect(summary(page)).toHaveText(" · 4 of 4 policy path(s) shown");
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow keeps the dropdown filters, the search and the reset", async ({ page }) => {
    const pageErrors = await openApp(page);
    await page.selectOption("#apFltCatalog", "cat2");
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["*All 1", "-Approval required 0", "No approval required 1"]);
    await page.selectOption("#apFltCatalog", "");

    await page.selectOption("#apFltFlag", "approverLowerTier");
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    expect(await pills(page, "apMemberTierPills")).toEqual(["*All 1", "-Control Plane 0", "Management Plane 1", "User Access 1"]);
    await page.selectOption("#apFltFlag", "");

    await page.fill("#apFltSearch", "tier0 admin");
    await expect(summary(page)).toHaveText(" · 2 of 4 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["*All 2", "Approval required 1", "No approval required 1"]);

    await pill(page, "apExpirationPills", "Fixed expiration").click();
    await page.selectOption("#apFltCatalog", "cat1");
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    await page.click("#apResetFilters");
    await expect(summary(page)).toHaveText(" · 4 of 4 policy path(s) shown");
    await expect(page.locator("#apFltSearch")).toHaveValue("");
    await expect(page.locator("#apFltCatalog")).toHaveValue("");
    expect(await pills(page, "apExpirationPills")).toEqual(["*All 4", "No expiration 2", "Fixed expiration 2"]);

    // Another snapshot: the policies of the Tier0 catalog, without findings. Its filters start from scratch.
    await pill(page, "apApprovalPills", /^Approval required/).click();
    await page.selectOption("#apSnapshot", "0");
    await expect(summary(page)).toHaveText(" · 3 of 3 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["*All 3", "Approval required 2", "No approval required 1"]);
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow exports the filtered policies", async ({ page }) => {
    const pageErrors = await openApp(page);
    await pill(page, "apTargetTypePills", "Groups").click();
    const [download] = await Promise.all([page.waitForEvent("download", (item) => item.suggestedFilename().endsWith(".csv")), page.click("#apExportFiltered")]);
    const lines = (await readFile(await download.path(), "utf8")).trim().split("\n");
    expect(lines).toHaveLength(4);
    expect(lines.some((line) => line.includes("HR App requests"))).toBe(false);
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow keeps the deep link to a policy", async ({ page }) => {
    const pageErrors = await openApp(page, "#flow=pol2");
    await expect(page.locator("#apFlowDetail")).toBeVisible();
    await expect(page.locator("#apFlowDetail")).toContainText("Tier0 approved");
    await expect(summary(page)).toHaveText(" · 1 of 4 policy path(s) shown");
    expect(await pills(page, "apApprovalPills")).toEqual(["*All 4", "Approval required 2", "No approval required 2"]);
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow classifies a policy by its target resources and shows the approval tier of the findings", async ({ page }) => {
    const pageErrors = await openApp(page);
    // The policy node of pol2 (grants the Control Plane target of pk1, approved by a User Access approver).
    await page.locator("#apSankey g.nodes rect").evaluateAll((rects) => {
        const rect = rects.find((node) => node.__data__ && node.__data__.id === "policy|pol2");
        rect.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    await expect(page.locator("#objectInspectorTitle")).toContainText("Tier0 approved");
    await expect(page.locator("#objectInspectorTitle .tier-badge")).toHaveText("Control Plane");
    const field = (label) => page.locator("#objectInspectorBody dt", { hasText: new RegExp(`^${label}$`) }).locator("xpath=following-sibling::dd[1]");
    await expect(field("Classification")).toHaveText("ControlPlane");
    await expect(field("Approval tier")).toHaveText("UserAccess");
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow explains declared and unknown target tiers and lists informational flags without counting them", async ({ page }) => {
    // pk3: one target with a tier declared in the Object Classification File, one without any classification;
    // pol4 (pk3) gets the informational flag of the unclassified target.
    const variant = structuredClone(findings);
    const latest = variant.snapshots[latestKey];
    latest.packages.pk3 = { targets: [{ tier: "ManagementPlane", source: "objectClassification", reason: "Landing zone 01", declaredBy: "Alternate Tier Level Attributes" }, { source: "unclassified" }] };
    latest.flags.pol4 = [{ id: "unclassifiedTarget", ruleId: "EO.2005", severity: "info", text: "EntraOps cannot classify the target group of this access package: Contoso Subscription." }];
    const root = await mkdtemp(join(tmpdir(), "entraops-access-package-flow-unclassified-"));
    extraFixtureRoots.push(root);
    const url = await buildFixture(root, variant);

    const pageErrors = await openApp(page, "#flow=pol4", url);
    const detail = page.locator("#apFlowDetail");
    await expect(detail).toBeVisible();
    const notes = detail.locator(".ap-classification-note");
    await expect(notes).toHaveCount(2);
    await expect(notes.nth(0)).toHaveAttribute("title", /declared by the Alternate Tier Level Attributes \(Landing zone 01\)/);
    await expect(notes.nth(1)).toHaveAttribute("title", /^Unclassified: this group has no role assignment and no tier from the Alternate Tier Level Attributes \(Group filters\) or the Object Classification File/);
    await expect(detail.locator(".status-chip", { hasText: "Unclassified" })).toHaveCount(1);
    // The informational flag is shown with its own icon, but the policy does not count as flagged (pol1 and pol3 are).
    await expect(detail.locator(".ca-gap-icon.info")).toHaveCount(1);
    await expect(page.locator("#apStatFlagged")).toHaveText("2");
    await expect(page.locator("#apFlagsBody .ca-gap-icon.info")).toHaveCount(1);
    await expect(page.locator("#apFlagsBody .ap-risk-stat-pill.info")).toHaveCount(1);
    expect(pageErrors).toEqual([]);
});

test("Access Package Flow collapses the groups of the risk flag list and remembers them", async ({ page }) => {
    const pageErrors = await openApp(page);
    // Group titles use the display names of the tiers.
    await expect(page.locator("#apFlagsBody .eo-group-title")).toHaveText(["Control Plane", "Management Plane"]);
    await page.locator("#apFlagsBody .eo-group-toggle", { hasText: "Management Plane" }).click();
    await expect(page.locator("#apFlagsBody .eo-group").nth(1)).toHaveClass(/collapsed/);
    await expect(page.locator("#apFlagsBody .eo-group-toggle").nth(1)).toHaveAttribute("aria-expanded", "false");
    await page.reload();
    await expect(page.locator("#apFlagsBody .eo-group").nth(1)).toHaveClass(/collapsed/);
    // Collapsed groups are rendered, only hidden.
    await expect(page.locator("#apFlagsBody .ca-gap-row")).toHaveCount(3);

    await page.click("#apCollapseAllRiskGroups");
    await expect(page.locator("#apFlagsBody .eo-group.collapsed")).toHaveCount(2);
    await expect(page.locator("#apCollapseAllRiskGroups")).toHaveText("Expand all");
    await page.click("#apCollapseAllRiskGroups");
    await expect(page.locator("#apFlagsBody .eo-group.collapsed")).toHaveCount(0);

    await page.selectOption("#apFlagGroup", "catalog");
    await expect(page.locator("#apFlagsBody .eo-group-title")).toHaveText(["Contoso Tier0 Catalog"]);
    await page.fill("#apFlagSearch", "no such flag");
    await expect(page.locator("#apFlagsBody")).toContainText("No risk flags match the current search.");
    await expect(page.locator("#apCollapseAllRiskGroups")).toBeDisabled();
    expect(pageErrors).toEqual([]);
});
