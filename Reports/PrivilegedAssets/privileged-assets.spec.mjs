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
let maesterAppUrl;
let twoFileAppUrl;
let findingsAppUrl;
let savedFindingsAppUrl;
let otherTenantFindingsAppUrl;
let catalogFindingsAppUrl;
let outsideFindingsAppUrl;
let noRulesAppUrl;
let catalogDataAppUrl;
let unclassifiedFindingsAppUrl;
let exceptionFindingsAppUrl;
let groupedFindingsAppUrl;
let expiredFindingsAppUrl;
let dataGapsFindingsAppUrl;

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
        // The service principal of a multi-tenant application is outside the home tenant for the findings (isForeign),
        // but an object of the home tenant: the script still sets its custom security attributes.
        objects: fixtureData.objects.map((entry) => entry.objectId === servicePrincipalId ? { ...entry, isForeign: true, isObjectOfOtherTenant: false } : entry),
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
    maesterAppUrl = await writeAppFixture("PrivilegedAssetsMaester", maesterData());
    const twoFileData = JSON.parse(JSON.stringify(fixtureData));
    twoFileData.classificationSettings.objectClassificationFile.entries.push(
        { objectId: groupId, objectType: "group", objectDisplayName: "PRG-Tier0-Admins", adminTierLevelName: "ControlPlane", justification: "Added by ServiceEM" }
    );
    twoFileAppUrl = await writeAppFixture("PrivilegedAssetsTwoFile", twoFileData);
    findingsAppUrl = await writeAppFixture("PrivilegedAssetsFindings", findingsData());
    // The saved findings of all rules (../Findings/data/findings.js) in their own Reports folders.
    savedFindingsAppUrl = await writeSavedFindingsFixture("saved", "t1");
    otherTenantFindingsAppUrl = await writeSavedFindingsFixture("othertenant", "t2");
    // Saved results of the current format: catalog category title and number, an Error and a deprecated (Excluded) rule.
    catalogFindingsAppUrl = await writeSavedFindingsFixture("catalog", "t1", [
        { ...savedRule("EO.3001", "permanentControlPlaneAssignment", "PrivilegedEAM", "JustInTimeAccess", "Permanent Control Plane role assignment", "High", [savedResult(userId, "Permanent.")]), CategoryTitle: "Just-in-time (catalog)", CategoryNumber: 3 },
        { ...savedRule("EO.5001", "agentPrivileged", "PrivilegedEAM", "WorkloadIdentities", "Agent identity with privileged access", "High", []), CategoryTitle: "Workload and agent identities", CategoryNumber: 1 },
        { ...savedRule("EO.3010", "privilegedRoleAlert", "TenantGovernance", "JustInTimeAccess", "Privileged role without administrator alerts", "Medium", [], "Error"), Reason: "The snapshot could not be read.", CategoryTitle: "Just-in-time (catalog)", CategoryNumber: 3 },
        { ...savedRule("EO.8099", "oldDrift", "PrivilegeHistory", "Drift", "Removed drift check", "Low", [], "Excluded"), Reason: "Deprecated: replaced by EO.8001.", CategoryTitle: "Drift", CategoryNumber: 8 }
    ]);
    noRulesAppUrl = await writeSavedFindingsFixture("norules", "t1", []);
    // A finding of a group outside the Privileged EAM export (for example an access package resource group).
    outsideFindingsAppUrl = await writeSavedFindingsFixture("outside", "t1", [
        savedRule("EO.6003", "unauthorizedAccess", "AccessPackageFlow", "AccessGovernance", "Unauthorized access to privileged access package resource", "High", [
            savedResult(groupId, "'PRG-Tier0-Admins' has 2 members without an access package assignment.", "group", {}, "in"),
            savedResult("abababab-abab-abab-abab-abababababab", "'Exclusion group' has 1 member without an access package assignment.", "group", {}, "out")
        ])
    ]);
    // Checks with failed instances of unclassified objects: counted apart and listed only on request.
    const unclassifiedPath = (id, service) => ({ ...savedResult(servicePrincipalId, `Unclassified object (counted as Tier 2) 'App B' reaches the Tier 1 service '${service}'.`, "serviceprincipal", { Role: "Owner", Service: service }, id), RuleId: "EO.1003" });
    unclassifiedFindingsAppUrl = await writeSavedFindingsFixture("unclassified", "t1", [
        { ...savedRule("EO.1003", "breach", "TierBreach", "TierBoundaries", "Assignment path reaches a Management Plane service", "High", [], "Skipped"),
            Reason: "Only unclassified objects are affected: 1 unclassified object(s) with 2 affected role assignments. Classify these objects (EO.2001) to evaluate this check: their tier is unknown, so they are not reported as findings.",
            UnclassifiedCount: 2, UnclassifiedResults: [unclassifiedPath("path-a", "Groups"), unclassifiedPath("path-b", "Users")] },
        { ...savedRule("EO.1001", "tier0Breach", "TierBreach", "TierBoundaries", "Tier 0 breach", "Critical", [savedResult(userId, "Admin A reaches a Control Plane service.", "user", { Role: "Owner", Service: "Billing" }, "path-c")]),
            UnclassifiedCount: 1, UnclassifiedResults: [unclassifiedPath("path-d", "Billing")] },
        savedRule("EO.2001", "unclassified", "PrivilegedAssets", "Classification", "Unclassified object", "Medium", [savedResult(servicePrincipalId, "No object tier is defined.", "serviceprincipal")])
    ]);
    // Findings accepted by the Finding Exceptions File: an active exception (expiring soon) and a stale one.
    const soon = new Date(Date.now() + 10 * 86400000).toISOString().slice(0, 10);
    const activeException = { RuleId: "EO.1001", InstanceId: "path2", ObjectId: userId, DisplayName: "Admin A", State: "RiskAccepted", Justification: "Migration to a Tier 0 account", AcceptedBy: "sec@contoso.com", AcceptedOn: "2026-01-01", ExpiresOn: soon, Reference: "CHG-1" };
    exceptionFindingsAppUrl = await writeSavedFindingsFixture("exceptions", "t1", [
        { ...savedRule("EO.1001", "tier0Breach", "TierBreach", "TierBoundaries", "Tier 0 breach", "Critical", [savedResult(servicePrincipalId, "App B reaches a Control Plane service.", "serviceprincipal", {}, "path1")]),
            AcceptedCount: 1, AcceptedResults: [{ ...savedResult(userId, "Admin A reaches a Control Plane service.", "user", {}, "path2"), Status: "RiskAccepted", Exception: { Key: "eo.1001|path2|", ...activeException } }],
            Exceptions: [
                { Key: "eo.1001|path2|", ...activeException, Status: "Active", MatchedCount: 1 },
                { Key: "eo.1001||gone", RuleId: "EO.1001", ObjectId: "gone", DisplayName: "Removed app", State: "Dismissed", Justification: "False positive", Status: "Stale", MatchedCount: 0 }
            ] },
        savedRule("EO.3001", "permanentControlPlaneAssignment", "PrivilegedEAM", "JustInTimeAccess", "Permanent Control Plane role assignment", "High", [savedResult(userId, "Permanent.", "user", {}, "ra1")]),
        { ...savedRule("EO.1004", "riskOnly", "TierBreach", "TierBoundaries", "Risk accepted only", "High", [], "Passed"), AcceptedCount: 1,
            AcceptedResults: [{ ...savedResult(groupId, "Accepted.", "group", {}, "g1"), Status: "RiskAccepted", Exception: { State: "RiskAccepted", Justification: "Accepted", ExpiresOn: soon } }] },
        { ...savedRule("EO.1005", "dismissedOnly", "TierBreach", "TierBoundaries", "Dismissed only", "Medium", [], "Passed"), AcceptedCount: 1,
            AcceptedResults: [{ ...savedResult(groupId, "False positive.", "group", {}, "g2"), Status: "Dismissed", Exception: { State: "Dismissed", Justification: "False positive" } }] }
    ], { ExceptionSettings: { FilePath: "./Classification/FindingExceptions.json", MaxDays: 90 } });
    // Several results of one object (grouped in the check panel), a note, a skipped check that is not applicable, an
    // expired exception of a result, readable evidence and a result outside the inventory with its tier name.
    const groupedEvidence = {
        Role: "Owner", Service: "Billing", Services: ["Billing", "Cost Management"], ServiceTierLevel: 0, PimAssignmentType: "Eligible", ActivationMaxDuration: "PT8H",
        SnapshotKey: "abc|2026-01-01", PathIds: ["hash-1", "hash-2"], Examples: [{ Identity: "guest@contoso.com", AccessPackage: "", AssignedRole: "Member" }], MoreExamples: false, Count: 2, TotalDrift: 2
    };
    groupedFindingsAppUrl = await writeSavedFindingsFixture("grouped", "t1", [
        { ...savedRule("EO.1001", "tier0Breach", "TierBreach", "TierBoundaries", "Tier 0 breach", "Critical", [
            savedResult(userId, "Admin A reaches Billing at path a.", "user", groupedEvidence, "path-a"),
            savedResult(userId, "Admin A reaches Billing at path b.", "user", { Role: "Owner", Service: "Billing" }, "path-b"),
            savedResult(servicePrincipalId, "App B reaches Billing.", "serviceprincipal", { Role: "Owner", Service: "Billing" }, "path-c")
        ]), Reason: "2 excluded groups could not be resolved.",
        Exceptions: [{ Key: "eo.1001|path-a|", RuleId: "EO.1001", InstanceId: "path-a", ObjectId: userId, DisplayName: "Admin A", State: "RiskAccepted", Justification: "Old", AcceptedBy: "x", AcceptedOn: "2019-10-01", ExpiresOn: "2020-01-01", Status: "Expired", MatchedCount: 1 }] },
        { ...savedRule("EO.3012", "permanentEligible", "PimRequestFlow", "JustInTimeAccess", "Permanent eligible assignment allowed", "Medium", [], "Skipped"), ReasonCode: "NotApplicable" },
        savedRule("EO.4003", "caExclusion", "TenantGovernance", "AccountProtection", "Control Plane user excluded from Conditional Access", "High", [
            { RuleId: "", Instance: { Id: "cap1", ObjectId: "33333333-3333-3333-3333-333333333333", ObjectType: "conditionalAccessPolicy", DisplayName: "Policy 1", AdminTierLevel: 2, AdminTierLevelName: "Unclassified" }, Evidence: {}, Message: "Policy 1 excludes Admin A." }
        ])
    ], { ExceptionSettings: { FilePath: "./Classification/FindingExceptions.json", MaxDays: 90 } });
    // Findings accepted at the evaluation by exceptions that have expired since then, next to an active one.
    const expiredException = { RuleId: "EO.1004", InstanceId: "g1", ObjectId: groupId, DisplayName: "PRG-Tier0-Admins", State: "RiskAccepted", Justification: "Until the migration", AcceptedBy: "sec@contoso.com", AcceptedOn: "2019-11-01", ExpiresOn: "2020-01-15", Reference: "CHG-2" };
    const expiredPathException = { ...expiredException, RuleId: "EO.1001", InstanceId: "path3", ObjectId: userId, DisplayName: "Admin A" };
    const activePathException = { ...activeException, InstanceId: "path2" };
    expiredFindingsAppUrl = await writeSavedFindingsFixture("expired", "t1", [
        { ...savedRule("EO.1001", "tier0Breach", "TierBreach", "TierBoundaries", "Tier 0 breach", "Critical", [savedResult(servicePrincipalId, "App B reaches a Control Plane service.", "serviceprincipal", {}, "path1")]),
            AcceptedCount: 2, AcceptedResults: [
                { ...savedResult(userId, "Admin A reaches a Control Plane service.", "user", {}, "path2"), Status: "RiskAccepted", Exception: { Key: "eo.1001|path2|", ...activePathException } },
                { ...savedResult(userId, "Admin A reaches another Control Plane service.", "user", {}, "path3"), Status: "RiskAccepted", Exception: { Key: "eo.1001|path3|", ...expiredPathException } }
            ],
            Exceptions: [{ Key: "eo.1001|path2|", ...activePathException, Status: "Active", MatchedCount: 1 }, { Key: "eo.1001|path3|", ...expiredPathException, Status: "Active", MatchedCount: 1 }] },
        { ...savedRule("EO.1004", "riskOnly", "TierBreach", "TierBoundaries", "Risk accepted only", "High", [], "Passed"), AcceptedCount: 1,
            AcceptedResults: [{ ...savedResult(groupId, "Accepted.", "group", {}, "g1"), Status: "RiskAccepted", Exception: { Key: "eo.1004|g1|", ...expiredException } }],
            Exceptions: [{ Key: "eo.1004|g1|", ...expiredException, Status: "Active", MatchedCount: 1 }] }
    ], { ExceptionSettings: { FilePath: "./Classification/FindingExceptions.json", MaxDays: 90 } });
    catalogDataAppUrl = await writeAppFixture("PrivilegedAssetsCatalogData", catalogData());
    // Data gaps of the evaluation (DataGaps of findings.json); the messages name tenant objects and are text, not HTML.
    dataGapsFindingsAppUrl = await writeSavedFindingsFixture("datagaps", "t1", undefined, {
        DataGaps: [
            { Code: "GroupOriginUnknown", Message: "The origin of 2 group(s) with role assignments (<img src=x onerror=window.__gapXss=1>, Admins) is unknown (permission Group-XTenantIdentitySync.Read.All missing?); groups synchronized from other tenants are not recognized.", Count: 2, RuleIds: ["EO.3001", "EO.4011"] },
            { Code: "ObjectClassificationFileMissing", Message: "The Object Classification File is enabled, but ./Classification/ObjectClassification.json does not exist.", Count: 1, RuleIds: ["EO.1001"] }
        ]
    });
});

function savedRule(ruleId, key, area, category, title, severity, results, status = "Failed") {
    return { RuleId: ruleId, Key: key, Area: area, Category: category, Title: title, CheckTitle: `${title} is checked.`, Description: `Description of ${ruleId}.`, Remediation: `Remediation of ${ruleId}.`, Effort: "Low", EffortDescription: `Effort of ${ruleId}.`, UserImpact: "Medium", UserImpactDescription: `User impact of ${ruleId}.`, Severity: severity, MaesterTestId: `MP.EOPS.${ruleId.slice(3)}`,
        References: [{ Title: `Learn page of ${ruleId}`, Url: `https://learn.microsoft.com/entra/${key}`, Type: "Learn" }, { Title: "Unsafe link", Url: "javascript:alert(1)", Type: "Learn" }],
        Status: status, Reason: null, Parameters: {}, EvaluatedCount: 3, FailedCount: results.length, Results: results };
}

function savedResult(objectId, message, objectType = "user", evidence = {}, instanceId = objectId) {
    return { RuleId: "", Instance: { Id: instanceId, ObjectId: objectId, ObjectType: objectType, DisplayName: "", AdminTierLevel: 0 }, Evidence: evidence, Message: message };
}

async function writeSavedFindingsFixture(name, tenantId, rules, extra = {}) {
    const reportsRoot = join(fixtureRoot, name, "Reports");
    await cp(join(reportsSourceDir, "shared"), join(reportsRoot, "shared"), { recursive: true });
    const findings = {
        SchemaVersion: "1.0", GeneratedAt: "2026-01-01T00:00:00Z", Generator: { Name: "EntraOps", Version: "1.2.0" }, TenantId: tenantId, TenantName: "contoso.onmicrosoft.com",
        Rules: rules || [
            savedRule("EO.1001", "tier0Breach", "TierBreach", "TierBoundaries", "Tier 0 breach", "Critical", [savedResult(servicePrincipalId, "App B reaches a Control Plane service.", "serviceprincipal", { Role: "Owner", Service: "Billing", Services: ["Billing", "Cost Management"], ScopeId: "/subscriptions/s1", AssignmentInstanceId: "EO_RA_tb1", PathIds: ["tbpath1", "tbpath2"] }, "path1")]),
            savedRule("EO.1002", "tierBreach", "PrivilegedAssets", "TierBoundaries", "Object tier below role assignments", "High", [savedResult(servicePrincipalId, "Shown from the data file.")]),
            savedRule("EO.3001", "permanentControlPlaneAssignment", "PrivilegedEAM", "JustInTimeAccess", "Permanent Control Plane role assignment", "High",
                [savedResult(userId.toUpperCase(), "User 'Admin A' holds the Control Plane role 'Global Administrator' (EntraID) as a permanent assignment.", "user", { RoleAssignmentInstanceId: "EO_RA_ga1" })]),
            savedRule("EO.3007", "noApprovalActivation", "PimRequestFlow", "JustInTimeAccess", "No approval to activate privileged role", "High", [savedResult("99999999-9999-9999-9999-999999999999", "Role without approval.", "roleSetting", { FlowId: "99999999-9999-9999-9999-999999999999|activation" }, "99999999-9999-9999-9999-999999999999.activation")]),
            savedRule("EO.6003", "unauthorizedAccess", "AccessPackageFlow", "AccessGovernance", "Unauthorized access to privileged access package resource", "High", [savedResult(groupId, "'PRG-Tier0-Admins' has 2 members without an access package assignment.")]),
            savedRule("EO.7002", "privilegedGroupOwner", "PrivilegedEAM", "OwnershipAndDelegation", "Owner of privileged group", "Medium", [], "Passed")
        ],
        ...extra
    };
    await mkdir(join(reportsRoot, "Findings", "data"), { recursive: true });
    await writeFile(join(reportsRoot, "Findings", "data", "findings.js"), `window.ENTRAOPS_FINDINGS = ${JSON.stringify(findings)};\n`, "utf8");
    return writeAppFixture("PrivilegedAssets", fixtureData, reportsRoot);
}

function maesterTestRecord(id, severity, title) {
    return {
        index: 1, id, title, name: `${id}: ${title}`, severity, result: "Failed", tags: ["Maester", id], helpUrl: `https://maester.dev/docs/tests/${id}`,
        block: "Maester/Entra", service: "", description: "Owners can <script>alert(1)</script> manage the app.\n\n#### Remediation action\n\n1. Remove owners\n2. Review [docs](https://maester.dev)\n",
        testResult: "Your tenant has issues:\n\n| Name | Status |\n| --- | --- |\n| App B | **Failed** |\n"
    };
}

function maesterData() {
    const ids = [["MT.1001", "Critical"], ["MT.1002", "High"], ["MT.1003", "Medium"], ["MT.1004", "Low"], ["MT.1005", "Medium"]];
    const tests = Object.fromEntries(ids.map(([id, severity]) => [id, maesterTestRecord(id, severity, `Title of ${id}`)]));
    const asset = (id, testIds) => ({
        system: "EntraID", anchorKind: "Instance", type: "ServicePrincipal", id, uniqueId: `object-${id.slice(0, 4)}`, displayName: "App B",
        userPrincipalName: "", portalLink: "https://entra.microsoft.com/#view/app", sources: ["Markdown", "GraphCache"], tests: testIds
    });
    const data = JSON.parse(JSON.stringify(fixtureData));
    data.maester = { sourceFile: "TestResults-2026-10-04-103542.json", executedAt: "2026-10-04T08:35:43Z", tenantId: "t1", tenantName: "contoso", totals: { total: 825, failed: 4, passed: 3, skipped: 0 }, affectedObjectCount: 49, matchedObjectCount: 2, tests };
    data.objects.find((o) => o.objectId === servicePrincipalId).maesterAssets = [asset(servicePrincipalId, ids.map(([id]) => id))];
    data.objects.find((o) => o.objectId === userId).maesterAssets = [asset(userId, ["MT.1002"])];
    return data;
}

// Data with the findings block of New-EntraOpsPrivilegedAssetsData (evaluated in PowerShell). The findings
// deliberately differ from the report rules, so the test shows which source the report uses.
function findingsData() {
    const rules = [
        ["EO.1001", "tierBreach", "Object tier below role assignments", "high"], ["EO.1002", "unclassified", "Unclassified object", "medium"],
        ["EO.1003", "ownerLowerTier", "Owner with lower tier", "high"], ["EO.1004", "ownsHigherTier", "Owns higher-tier object", "high"],
        ["EO.1005", "parentLowerTier", "Identity parent with lower tier", "medium"], ["EO.1006", "sponsorMissing", "No sponsor", "medium"],
        ["EO.1007", "deviceNotPaw", "Owns non-PAW devices", "medium"], ["EO.1008", "pawMissing", "No associated PAW", "info"],
        ["EO.1009", "workAccountMissing", "No associated work account", "info"], ["EO.1010", "hybridPrivileged", "Synchronized Control Plane identity", "high"],
        ["EO.1011", "restrictedManagementGap", "Restricted management not applied", "medium"], ["EO.1012", "foreign", "Outside home tenant (PowerShell)", "info"]
    ];
    const data = JSON.parse(JSON.stringify(fixtureData));
    data.findings = {
        rules: rules.map(([id, key, title, reportSeverity]) => ({ id, key, title, description: `${title}.`, severity: "Medium", reportSeverity, maesterTestId: `MP.EOPS.${id.slice(3)}`, status: "Failed", evaluatedCount: 1, failedCount: 1 })),
        byObject: { [groupId]: ["foreign"] }
    };
    return data;
}

// Data with the findings block of the current format: check title, remediation, catalog category and reason.
function catalogData() {
    const data = JSON.parse(JSON.stringify(fixtureData));
    data.findings = {
        rules: [
            { id: "EO.4001", key: "hybridPrivileged", title: "Synchronized Control Plane identity", checkTitle: "No Control Plane identity is synchronized.", description: "Synchronized.", remediation: "Use cloud-only accounts.", severity: "High", reportSeverity: "high", category: "AccountProtection", categoryTitle: "Account protection", categoryNumber: 4, maesterTestId: "MP.EOPS.4001", status: "Failed", reason: "", evaluatedCount: 4, failedCount: 1 },
            { id: "EO.2001", key: "unclassified", title: "Unclassified object", checkTitle: "Every privileged object has a tier.", description: "Unclassified.", remediation: "Classify it.", severity: "Medium", reportSeverity: "medium", category: "Classification", categoryTitle: "Classification", categoryNumber: 2, maesterTestId: "MP.EOPS.2001", status: "Error", reason: "Classification data could not be read.", evaluatedCount: 0, failedCount: 0 },
            { id: "EO.4010", key: "foreign", title: "Outside home tenant", checkTitle: "No object of another tenant.", description: "Foreign.", remediation: "", severity: "Info", reportSeverity: "info", category: "AccountProtection", categoryTitle: "Account protection", categoryNumber: 4, maesterTestId: "", status: "Excluded", reason: "Deprecated.", evaluatedCount: 0, failedCount: 0 }
        ],
        byObject: { [userId]: ["hybridPrivileged"], [groupId]: ["foreign"] }
    };
    return data;
}

async function writeAppFixture(folderName, data, reportsRoot = join(fixtureRoot, "Reports")) {
    const appFixtureDir = join(reportsRoot, folderName);
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
    // One line per object: the highest severity, the number of findings and the most severe one; all in the side panel.
    await expect(appRow.locator(".pai-findings-cell .pai-ftop")).toHaveText("Object tier below role assignments");
    await expect(appRow.locator(".pai-findings-cell .pai-sev")).toHaveText("High");
    const userRow = page.locator(`#paiTableBody tr[data-object="${userId}"]`);
    // Unclassified: reported as an unclassified object, not as a tier breach as well.
    await expect(userRow.locator(".pai-findings-cell .pai-fcount")).toHaveText("6 findings");
    await userRow.locator(".pai-findings-cell button[data-findings-more]").click();
    await expect(page.locator("#paiDrawerFindings")).toContainText("Synchronized Control Plane identity");
    await expect(page.locator("#paiDrawerFindings")).not.toContainText("Object tier below role assignments");
    await expect(page.locator("#paiDrawerFindings")).toContainText("Owns non-PAW devices");
    await page.keyboard.press("Escape");
    await appRow.locator(".pai-findings-cell button[data-findings-more]").click();
    await expect(page.locator("#paiDrawerFindings")).toContainText("Owner with lower tier");
    await page.keyboard.press("Escape");

    await page.click("#paiMoreFilters");
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

    const stored = await page.evaluate(() => JSON.parse(localStorage.getItem("entraops.privilegedAssets.objectClassification.v2")).upserts);
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
    const entry = await page.evaluate((id) => JSON.parse(localStorage.getItem("entraops.privilegedAssets.objectClassification.v2")).upserts[id], groupId);
    expect(entry.adminTierLevelName).toBe("ManagementPlane");
    expect(entry.justification).toBe("=Imported");
});

test("Maester failed tests show as findings and open a detail blade", async ({ page }) => {
    const pageErrors = await openApp(page, maesterAppUrl);
    const appRow = page.locator(`#paiTableBody tr[data-object="${servicePrincipalId}"]`);

    // The most severe finding of the object is a Maester test; the count includes the Maester tests.
    await expect(appRow.locator(".pai-findings-cell .pai-sev")).toHaveText("Critical");
    await expect(appRow.locator(".pai-findings-cell .pai-ftop")).toContainText("Maester MT.1001");
    await expect(appRow.locator(".pai-findings-cell .pai-fcount")).toHaveText("7 findings");
    await expect(page.locator(`#paiTableBody tr[data-object="${groupId}"] .pai-findings-cell`)).not.toContainText("Maester");

    await page.selectOption("#paiFilterFinding", "maester:MT.1002");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(2);
    await page.selectOption("#paiFilterFinding", "__maester");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(2);
    await page.click("#paiResetFilters");

    await appRow.locator(".pai-findings-cell button[data-findings-more]").click();
    await expect(page.locator("#paiDrawerMaester li")).toHaveCount(5);
    const chip = page.locator('#paiDrawerMaester button[data-maester-open="MT.1001"]');
    await chip.click();
    const blade = page.locator("#paiMaesterBlade");
    await expect(blade).toHaveClass(/open/);
    await expect(page.locator("#paiMaesterTitle")).toHaveText("Title of MT.1001");
    await expect(blade).toContainText("Remediation action");
    await expect(blade.locator(".pai-md-table td").first()).toHaveText("App B");
    await expect(blade.locator(".pai-md script")).toHaveCount(0);
    await expect(blade).toContainText("object-2222");
    await expect(blade.locator('a[href="https://maester.dev/docs/tests/MT.1001"]')).toHaveCount(2);
    await expect(page).toHaveURL(new RegExp(`#asset=${servicePrincipalId}&maester=MT.1001$`));

    await page.keyboard.press("Escape");
    await expect(blade).not.toHaveClass(/open/);
    // The object stays open below the blade and gets the focus back.
    await expect(page.locator("#paiDrawer")).toHaveClass(/open/);
    await expect(chip).toBeFocused();
    expect(pageErrors).toEqual([]);
});

for (const viewport of [{ name: "desktop", width: 1600, height: 900 }, { name: "laptop", width: 1175, height: 800 }]) {
    test(`${viewport.name} keeps the inventory inside the viewport`, async ({ page }) => {
        await page.setViewportSize(viewport);
        await openApp(page);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow).toBeLessThanOrEqual(1);
    });
}

const storeKey = "entraops.privilegedAssets.objectClassification.v2";
const legacyStoreKey = "entraops.privilegedAssets.objectClassification.v1";

async function openWithStoredWorklist(page, url, key, value) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(url);
    await page.evaluate(([storageKey, stored]) => { localStorage.clear(); localStorage.setItem(storageKey, JSON.stringify(stored)); }, [key, value]);
    await page.reload();
    await expect(page.locator("#paiTableBody tr")).toHaveCount(4);
    await page.evaluate(() => {
        window.__downloads = [];
        const createObjectURL = URL.createObjectURL;
        URL.createObjectURL = (blob) => { blob.text().then((text) => window.__downloads.push(text)); return createObjectURL(blob); };
    });
    await openClassification(page);
    return pageErrors;
}

async function downloadedFile(page) {
    await page.click("#paiExportFile");
    await expect.poll(() => page.evaluate(() => window.__downloads.length)).toBe(1);
    return JSON.parse(await page.evaluate(() => window.__downloads[0]));
}

test("v1 worklist saved before a repository file entry was added keeps the new file entry", async ({ page }) => {
    const legacy = {
        tenant: fixtureData.tenantName,
        entries: { [userId]: { objectId: userId, objectType: "user", objectDisplayName: "Admin A", adminTierLevelName: "ManagementPlane", justification: "Local edit" } }
    };
    const pageErrors = await openWithStoredWorklist(page, twoFileAppUrl, legacyStoreKey, legacy);

    const notice = page.locator("#paiFileChanged");
    await expect(notice).toBeVisible();
    await expect(notice).toHaveAttribute("role", "status");
    await expect(notice).toContainText("repository Object Classification File changed");
    const groupRow = page.locator(`#paiWorklistBody tr[data-worklist="${groupId}"]`);
    await expect(groupRow).toContainText("In repository file");
    await expect(groupRow).not.toContainText("Removed");
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${userId}"]`)).toContainText("Changed");

    const rows = await downloadedFile(page);
    expect(rows.map((row) => row.ObjectId)).toEqual([userId, groupId]);
    expect(rows.find((row) => row.ObjectId === userId).AdminTierLevelName).toBe("ManagementPlane");
    expect(rows.find((row) => row.ObjectId === groupId).Justification).toBe("Added by ServiceEM");

    await page.click("#paiFileChangedKeep");
    await expect(notice).toBeHidden();
    const stored = await page.evaluate((key) => JSON.parse(localStorage.getItem(key)), storeKey);
    expect(Object.keys(stored.upserts)).toEqual([userId]);
    expect(stored.removals).toEqual([]);
    expect(await page.evaluate((key) => localStorage.getItem(key), legacyStoreKey)).toBeNull();
    await page.reload();
    await expect(page.locator("#paiFileChanged")).toBeHidden();
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${groupId}"]`)).toContainText("In repository file");
    expect(pageErrors).toEqual([]);
});

test("local delta is rebased onto a changed repository file", async ({ page }) => {
    const stored = {
        version: 2, tenant: fixtureData.tenantName, baseFingerprint: "stale",
        upserts: { [servicePrincipalId]: { objectId: servicePrincipalId, objectType: "serviceprincipal", objectDisplayName: "App B", adminTierLevelName: "ControlPlane", justification: "Holds PRA" } },
        removals: [userId, "99999999-9999-9999-9999-999999999999"]
    };
    const pageErrors = await openWithStoredWorklist(page, twoFileAppUrl, storeKey, stored);

    await expect(page.locator("#paiFileChanged")).toBeVisible();
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${userId}"]`)).toContainText("Removed");
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${groupId}"]`)).toContainText("In repository file");
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${servicePrincipalId}"]`)).toContainText("Added");
    await expect(page.locator("#paiWorklistBody tr")).toHaveCount(3);
    const rows = await downloadedFile(page);
    expect(rows.map((row) => row.ObjectId).sort()).toEqual([servicePrincipalId, groupId].sort());

    page.once("dialog", (dialog) => dialog.accept());
    await page.click("#paiFileChangedReset");
    await expect(page.locator("#paiFileChanged")).toBeHidden();
    await expect(page.locator("#paiWorklistMeta")).toContainText("2 entries · 0 pending changes");
    expect(await page.evaluate((key) => localStorage.getItem(key), storeKey)).toBeNull();
    expect(pageErrors).toEqual([]);
});

test("unchanged entries removed from the repository file are not restored as added", async ({ page }) => {
    // Saved against the two-entry file; the one-entry file no longer contains the group.
    const stored = { version: 2, tenant: fixtureData.tenantName, baseFingerprint: "stale", upserts: {}, removals: [] };
    await openWithStoredWorklist(page, appUrl, storeKey, stored);

    await expect(page.locator("#paiFileChanged")).toBeVisible();
    await expect(page.locator("#paiWorklistBody tr")).toHaveCount(1);
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${userId}"]`)).toContainText("In repository file");
    await expect(page.locator("#paiWorklistMeta")).toContainText("1 entries · 0 pending changes");
});

test("matching repository file fingerprint shows no notice", async ({ page }) => {
    await openApp(page);
    await openClassification(page);
    await page.fill("#paiAddObject", `App B (${servicePrincipalId})`);
    await page.click("#paiAddButton");
    await page.reload();
    await expect(page.locator(`#paiWorklistBody tr[data-worklist="${servicePrincipalId}"]`)).toContainText("Added");
    await expect(page.locator("#paiFileChanged")).toBeHidden();
});

test("shows the findings evaluated in PowerShell and re-evaluates them for What-if", async ({ page }) => {
    const pageErrors = await openApp(page, findingsAppUrl);
    const appRow = page.locator(`#paiTableBody tr[data-object="${servicePrincipalId}"]`);
    const groupRow = page.locator(`#paiTableBody tr[data-object="${groupId}"]`);

    await expect(groupRow).toContainText("Outside home tenant (PowerShell)");
    await expect(appRow).not.toContainText("Owner with lower tier");

    await page.check("#paiWhatIf");
    await expect(appRow.locator(".pai-findings-cell .pai-fcount")).toHaveText("2 findings");
    await appRow.locator(".pai-findings-cell button[data-findings-more]").click();
    await expect(page.locator("#paiDrawerFindings")).toContainText("Owner with lower tier");
    await expect(page.locator("#paiDrawerFindings")).toContainText("What-if");
    await page.keyboard.press("Escape");
    await expect(groupRow).not.toContainText("Outside home tenant");
    expect(pageErrors).toEqual([]);
});

test("filters by object type, sub type and classification pills with live counts", async ({ page }) => {
    const pageErrors = await openApp(page);
    const typePills = page.locator("#paiTypePills");
    await expect(typePills.locator('[data-value="user"] .eo-pill-count')).toHaveText("2");
    await expect(page.locator("#paiSubTypeRow")).toBeHidden();

    await typePills.locator('[data-value="user"]').click();
    await expect(page.locator("#paiTableBody tr")).toHaveCount(2);
    await expect(page.locator("#paiSubTypeRow")).toBeVisible();
    await page.locator('#paiSubTypePills [data-value="Guest"]').click();
    await expect(page.locator("#paiTableBody tr")).toHaveCount(1);
    await expect(page.locator("#paiTableBody")).toContainText("=Guest D");

    // A second click on the active pill shows all objects of the type again.
    await typePills.locator('[data-value="user"]').click();
    await expect(page.locator("#paiTableBody tr")).toHaveCount(4);

    await page.locator('#paiTierPills [data-value="ManagementPlane"]').click();
    await expect(page.locator("#paiTableBody tr")).toHaveCount(1);
    await expect(typePills.locator('[data-value="user"]')).toBeDisabled();
    await expect(typePills.locator('[data-value="serviceprincipal"] .eo-pill-count')).toHaveText("1");
    await page.click("#paiResetFilters");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(4);
    await expect(page.locator("#paiFindingsNote")).toContainText("not loaded");
    expect(pageErrors).toEqual([]);
});

test("shows the saved findings of the other EntraOps rules on their objects", async ({ page }) => {
    const pageErrors = await openApp(page, savedFindingsAppUrl);
    const appRow = page.locator(`#paiTableBody tr[data-object="${servicePrincipalId}"]`);
    const userRow = page.locator(`#paiTableBody tr[data-object="${userId}"]`);
    const groupRow = page.locator(`#paiTableBody tr[data-object="${groupId}"]`);

    await expect(appRow.locator(".pai-findings-cell .pai-sev")).toHaveText("Critical");
    await expect(appRow.locator(".pai-findings-cell .pai-ftop")).toHaveText("Tier 0 breach");
    // Outside What-if the inventory shows the saved results of the Privileged Assets checks (not the findings block of
    // the data file): the group has only the saved access package finding.
    await expect(groupRow.locator(".pai-findings-cell .pai-fcount")).toHaveText("1 finding");
    await groupRow.locator(".pai-findings-cell button[data-findings-more]").click();
    await expect(page.locator("#paiDrawerFindings")).toContainText("Unauthorized access to privileged access package resource");
    // The source is named once, as the link to its report.
    await expect(page.locator("#paiDrawerFindings")).not.toContainText("Access Package Flow · Access Package Flow");
    await page.keyboard.press("Escape");
    // The Privileged Assets rules come from the data file only (not twice).
    await expect(page.locator("#paiFindingsNote")).toContainText("1 finding(s) of 1 rule(s) concern roles");

    await page.selectOption("#paiFilterFinding", "rule:EO.3001");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(1);
    await expect(userRow).toBeVisible();
    await page.selectOption("#paiFilterFinding", "sev:Critical");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(1);
    await expect(appRow).toBeVisible();
    await page.click("#paiResetFilters");
    await page.fill("#paiSearch", "eo.6003");
    await expect(page.locator("#paiTableBody tr")).toHaveCount(1);
    await expect(groupRow).toBeVisible();
    await page.click("#paiResetFilters");

    await page.click(`#paiTableBody button[data-open="${userId}"]`);
    const findings = page.locator("#paiDrawerFindings");
    await expect(findings.locator(".pai-fgroup-title")).toContainText(["Just-in-time access"]);
    await expect(findings).toContainText("as a permanent assignment.");
    await expect(findings.locator(`a[href="../EamDashboard/index.html#asset=${userId}"]`)).toHaveCount(1);
    await page.keyboard.press("Escape");

    await page.check("#paiWhatIf");
    await expect(page.locator("#paiWhatIfNote")).toBeVisible();
    await expect(appRow).toContainText("Tier 0 breach");
    expect(pageErrors).toEqual([]);
});

test("ignores saved findings of another tenant", async ({ page }) => {
    const pageErrors = await openApp(page, otherTenantFindingsAppUrl);
    await expect(page.locator("#paiFindingsNote")).toContainText("belong to tenant t2");
    await expect(page.locator(`#paiTableBody tr[data-object="${servicePrincipalId}"]`)).not.toContainText("Tier 0 breach");
    expect(pageErrors).toEqual([]);
});

async function openFindingsView(page, url) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${url}?view=findings`);
    await expect(page.locator("#secPaiFindingsView")).toBeVisible();
    await expect(page.locator("#secPaiInventory")).toBeHidden();
    return pageErrors;
}

test("Findings view lists the checks by category", async ({ page }) => {
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    await expect(page.locator("#paiViewTitle")).toHaveText("Findings");
    await expect(page.locator('#paiRuleStats [data-rule-stat="Failed"] .stat-value')).toHaveText("5");
    await expect(page.locator('#paiRuleStats [data-rule-stat="Passed"] .stat-value')).toHaveText("1");
    await expect(page.locator("#paiRuleList .eo-group-title")).toHaveText(["Tier boundaries", "Just-in-time access", "Access governance", "Ownership and delegation"]);
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1001"]')).toContainText("Critical");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.7002"]')).toContainText("Passed");

    await page.locator('#paiRuleStatusPills [data-value="Passed"]').click();
    await expect(page.locator("#paiRuleList tr[data-rule]")).toHaveCount(1);
    await page.click("#paiRuleReset");
    await page.locator('#paiRuleSeverityPills [data-value="Critical"]').click();
    await expect(page.locator("#paiRuleList tr[data-rule]")).toHaveCount(1);
    await page.click("#paiRuleReset");
    await page.fill("#paiRuleSearch", "mp.eops.6003");
    await expect(page.locator("#paiRuleList tr[data-rule]")).toHaveCount(1);
    await page.click("#paiRuleReset");

    // The check with its description, remediation and affected objects, linked to the object in the inventory.
    await page.locator('#paiRuleList tr[data-rule="EO.3001"] [data-rule-open]').click();
    const blade = page.locator("#paiRuleBlade");
    await expect(blade).toHaveClass(/open/);
    await expect(page.locator("#paiRuleTitle")).toHaveText("Permanent Control Plane role assignment is checked.");
    await expect(blade).toContainText("Remediation of EO.3001.");
    await expect(blade).toContainText("Effort of EO.3001.");
    await expect(blade).toContainText("User impact of EO.3001.");
    // Each affected object links to the role assignment and the object in the other reports.
    await expect(blade.locator('.pai-result-links a[href="../EamDashboard/index.html#assignment=EO_RA_ga1"]')).toHaveCount(1);
    await expect(blade.locator(`.pai-result-links a[href="../AccessPathMap/index.html#node=${userId.toUpperCase()}"]`)).toHaveCount(1);
    await expect(blade.locator('a[href*="Test.MP.EOPS.3001.md"]')).toHaveCount(1);
    await expect(page).toHaveURL(/\?view=findings#rule=EO\.3001$/);
    await blade.locator(`button[data-open="${userId}"]`).click();
    await expect(blade).not.toHaveClass(/open/);
    await expect(page.locator("#paiDrawer")).toHaveClass(/open/);

    // From the object back to all affected objects of the check.
    await page.locator('#paiDrawerFindings [data-rule-open="EO.3001"]').click();
    await expect(page.locator("#paiDrawer")).not.toHaveClass(/open/);
    await expect(blade).toHaveClass(/open/);
    await page.keyboard.press("Escape");
    await expect(blade).not.toHaveClass(/open/);

    // Results outside the inventory link to their object in the source report: the PIM role setting and the tier breach path.
    await page.locator('#paiRuleList tr[data-rule="EO.3007"] [data-rule-open]').click();
    await expect(blade.locator('.pai-result-links a[href="../PimRequestFlow/index.html#flow=99999999-9999-9999-9999-999999999999%7Cactivation"]')).toHaveCount(1);
    await expect(blade.locator('.pai-result-links a[href="../ConfigurationAnalyzer/index.html#object=microsoft.entra.rolesetting%7C99999999-9999-9999-9999-999999999999"]')).toHaveCount(1);
    await page.keyboard.press("Escape");
    await page.locator('#paiRuleList tr[data-rule="EO.1001"] [data-rule-open]').click();
    await expect(blade.locator(`.pai-result-links a[href="../TierBreachAnalyzer/index.html#sel=${encodeURIComponent([servicePrincipalId, "Owner", "Billing", "/subscriptions/s1", "tbpath1"].join("||"))}"]`)).toHaveCount(1);
    await expect(blade.locator('.pai-result-links a[href="../EamDashboard/index.html#assignment=EO_RA_tb1"]')).toHaveCount(1);
    // A list in the evidence (the services of one assignment) shows one value per line; the path IDs are technical details.
    await expect(blade.locator(".pai-evidence:not(.pai-evidence-technical) > .pai-evidence-list dd .pai-evidence-item")).toHaveText(["Billing", "Cost Management"]);
    await expect(blade.locator(".pai-evidence-technical .pai-evidence-item")).toHaveText(["tbpath1", "tbpath2"]);
    expect(pageErrors).toEqual([]);
});

test("Findings view collapses categories and keeps them collapsed after a reload", async ({ page }) => {
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    const group = page.locator('#paiRuleList .eo-group[data-group="TierBoundaries"]');
    const toggle = group.locator("[data-group-toggle]");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toggle).toBeFocused();
    await expect(group.locator('tr[data-rule="EO.1001"]')).toBeHidden();
    // The collapsed category keeps its status summary; the other categories stay open.
    await expect(group.locator(".eo-group-meta")).toContainText("failed");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.3001"]')).toBeVisible();

    await page.reload();
    await expect(page.locator('#paiRuleList .eo-group[data-group="TierBoundaries"] [data-group-toggle]')).toHaveAttribute("aria-expanded", "false");

    await page.click("#paiRuleCollapseAll");
    await expect(page.locator("#paiRuleList tr[data-rule]:visible")).toHaveCount(0);
    await expect(page.locator("#paiRuleCollapseAll")).toHaveText("Expand all");
    await page.click("#paiRuleCollapseAll");
    await expect(page.locator("#paiRuleList .eo-group.collapsed")).toHaveCount(0);
    await expect(page.locator("#paiRuleCollapseAll")).toHaveText("Collapse all");
    expect(pageErrors).toEqual([]);
});

test("Findings view accepts findings and exports the Finding Exceptions File", async ({ page }) => {
    const pageErrors = await openFindingsView(page, exceptionFindingsAppUrl);
    await page.evaluate(() => {
        window.__downloads = [];
        const createObjectURL = URL.createObjectURL;
        URL.createObjectURL = (blob) => { blob.text().then((text) => window.__downloads.push(text)); return createObjectURL(blob); };
    });
    // The accepted finding is counted apart; the file exceptions are listed with their status.
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1001"] .pai-rule-accepted-hint')).toHaveText("+1 risk accepted");
    // A failed check keeps its status; only a check without open findings is marked as risk accepted.
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1001"] .pai-rule-risk-chip')).toHaveCount(0);
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1004"] .pai-status')).toHaveText(/Passed/);
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1004"] .pai-rule-risk-chip')).toHaveText("Risk accepted");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1005"] .pai-rule-accepted-hint')).toHaveText("+1 dismissed");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1005"] .pai-rule-risk-chip')).toHaveCount(0);
    await expect(page.locator('#paiRuleStats [data-rule-stat="__exceptions"] .stat-value')).toHaveText("2");
    await expect(page.locator('#paiRuleStats [data-rule-stat="__exceptions"] .stat-sub')).toHaveText("1 active (1 expiring soon) · 1 without finding");
    const list = page.locator("#paiExceptionBody");
    await expect(list.locator("tr")).toHaveCount(2);
    await expect(list.locator('tr[data-exception="eo.1001|path2|"]')).toContainText("Risk accepted");
    await expect(list.locator('tr[data-exception="eo.1001|path2|"]')).toContainText("Soon");
    await expect(list.locator('tr[data-exception="eo.1001|path2|"] .status-chip')).toHaveText("Active");
    await expect(list.locator('tr[data-exception="eo.1001||gone"] .status-chip')).toHaveText("No finding");
    await expect(page.locator("#paiExceptionExport")).toHaveText("Export FindingExceptions.json");

    // The panel of the check lists the accepted finding on request.
    await page.locator('#paiRuleList tr[data-rule="EO.1001"] [data-rule-open]').click();
    const body = page.locator("#paiRuleBody");
    await expect(body.locator(".pai-rule-accepted")).toContainText("1 accepted finding (1 risk accepted)");
    await expect(body.locator("#paiRuleResultsBody tr.pai-rule-accepted-row")).toHaveCount(0);
    await body.locator("#paiRuleShowAccepted").check();
    await expect(body.locator("#paiRuleResultsBody tr.pai-rule-accepted-row")).toContainText("Risk accepted");
    await page.keyboard.press("Escape");

    // Accept a finding: the form checks the justification and the longest acceptance (90 days).
    await page.locator('#paiRuleList tr[data-rule="EO.3001"] [data-rule-open]').click();
    await body.locator('[data-accept="ra1"]').click();
    const form = body.locator("#paiAcceptForm");
    await expect(form.locator('textarea[name="Justification"]')).toBeFocused();
    await form.locator('button[type="submit"]').click();
    await expect(form.locator(".pai-accept-error")).toHaveText("Enter a justification.");
    await form.locator('textarea[name="Justification"]').fill("Emergency access account");
    await form.locator('input[name="ExpiresOn"]').fill(new Date(Date.now() + 200 * 86400000).toISOString().slice(0, 10));
    await form.locator('button[type="submit"]').click();
    await expect(form.locator(".pai-accept-error")).toContainText("at most 90 days");
    await form.locator('select[name="State"]').selectOption("Dismissed");
    await form.locator('input[name="ExpiresOn"]').fill("");
    await form.locator('input[value="object"]').check();
    await form.locator('input[name="AcceptedBy"]').fill("sec@contoso.com");
    await form.locator('button[type="submit"]').click();
    await expect(body.locator("#paiAcceptForm")).toHaveCount(0);
    await expect(body.locator("#paiRuleResultsBody")).toContainText("Pending - export the file");
    await page.keyboard.press("Escape");

    const added = list.locator(`tr[data-exception="eo.3001||${userId}"]`);
    await expect(added.locator(".status-chip")).toHaveText("Added");
    await expect(added).toContainText("All findings of the object");
    await expect(page.locator("#paiExceptionMeta")).toHaveText("3 exceptions · 1 pending changes");
    // Remove the stale exception, then export the file to commit.
    await list.locator('tr[data-exception="eo.1001||gone"] [data-exception-remove]').click();
    await expect(list.locator('tr[data-exception="eo.1001||gone"] .status-chip')).toHaveText("Removed");
    await page.click("#paiExceptionExport");
    await expect.poll(() => page.evaluate(() => window.__downloads.length)).toBe(1);
    const exported = JSON.parse(await page.evaluate(() => window.__downloads[0]));
    expect(exported.map((entry) => entry.RuleId + " " + (entry.InstanceId || entry.ObjectId))).toEqual(["EO.1001 path2", `EO.3001 ${userId}`]);
    expect(exported[1]).toMatchObject({ State: "Dismissed", Justification: "Emergency access account", AcceptedBy: "sec@contoso.com", DisplayName: "Admin A" });
    expect(exported[1].ExpiresOn).toBeUndefined();
    expect(exported[0]).not.toHaveProperty("Status");

    // The changes are kept in this browser until the next evaluation brings them in the file.
    await page.reload();
    await expect(page.locator("#paiExceptionMeta")).toHaveText("2 exceptions · 2 pending changes");
    page.once("dialog", (dialog) => dialog.accept());
    await page.click("#paiExceptionReset");
    await expect(page.locator("#paiExceptionMeta")).toHaveText("2 exceptions · 0 pending changes");
    expect(pageErrors).toEqual([]);
});

test("Findings view opens a check from a deep link and lists the affected objects outside the inventory", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${savedFindingsAppUrl}?view=findings#rule=EO.3007`);
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page.locator("#paiRuleBody")).toContainText("99999999-9999-9999-9999-999999999999");
    await expect(page.locator("#paiRuleBody")).toContainText("Role without approval.");
    // Object types of results outside the inventory use the same casing as the inventory types.
    await expect(page.locator("#paiRuleResultsBody td").first()).toContainText("Role setting");
    // The resources of the rule (https links only, opened in a new tab) and the evidence of a result.
    const references = page.locator("#paiRuleReferences a");
    await expect(references).toHaveCount(1);
    await expect(references.first()).toHaveAttribute("href", "https://learn.microsoft.com/entra/noApprovalActivation");
    await expect(references.first()).toHaveAttribute("target", "_blank");
    await expect(page.locator("#paiRuleReferences")).toContainText("Learn page of EO.3007");
    await expect(page.locator("#paiRuleReferences")).toContainText("Microsoft Learn");
    const evidence = page.locator("#paiRuleResultsBody .pai-evidence");
    // Only an internal ID: the evidence is one collapsed "Technical details" section with a readable label.
    await expect(evidence).toHaveCount(1);
    await expect(evidence.locator("summary")).toHaveText("Technical details (1)");
    await expect(evidence.locator("dt")).toHaveText(["Flow ID"]);
    await expect(evidence.locator("dd")).toHaveText(["99999999-9999-9999-9999-999999999999|activation"]);
    expect(pageErrors).toEqual([]);
});

test("Findings view shows the data gaps of the evaluation above the results, as text", async ({ page }) => {
    const pageErrors = await openFindingsView(page, dataGapsFindingsAppUrl);
    const box = page.locator("#paiDataGaps");
    await expect(box).toBeVisible();
    await expect(box.locator(".callout-title")).toHaveText("Data gaps");
    const boxTop = (await box.boundingBox()).y;
    expect(boxTop).toBeLessThan((await page.locator("#secPaiRules").boundingBox()).y);
    expect(boxTop).toBeLessThan((await page.locator("#paiRuleStats").boundingBox()).y);
    await expect(box.locator("li[data-gap]")).toHaveCount(2);
    const origin = box.locator('li[data-gap="GroupOriginUnknown"]');
    // Tenant data is shown as text: the markup in a group name is not rendered.
    await expect(origin.locator(".pai-data-gap-message")).toContainText("(<img src=x onerror=window.__gapXss=1>, Admins)");
    await expect(box.locator("img")).toHaveCount(0);
    expect(await page.evaluate(() => window.__gapXss)).toBeUndefined();
    // Checks of the results open their panel; checks that the results do not have stay text.
    await expect(origin.locator(".pai-data-gap-rules")).toHaveText("Affected checks: EO.3001, EO.4011");
    await expect(origin.locator("[data-rule-open]")).toHaveCount(1);
    await expect(box.locator('li[data-gap="ObjectClassificationFileMissing"] .pai-data-gap-rules')).toHaveText("Affected check: EO.1001");
    await origin.locator('[data-rule-open="EO.3001"]').click();
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page).toHaveURL(/\?view=findings#rule=EO\.3001$/);
    expect(pageErrors).toEqual([]);
});

test("Findings view shows no data gaps box for results without data gaps", async ({ page }) => {
    // Results of earlier versions have no DataGaps.
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    await expect(page.locator('#paiRuleStats [data-rule-stat="Failed"] .stat-value')).toHaveText("5");
    await expect(page.locator("#paiDataGaps")).toBeHidden();
    await expect(page.locator("#paiDataGaps")).toBeEmpty();
    expect(pageErrors).toEqual([]);
});

test("Findings view shows the Privileged Assets checks of the data file without saved results", async ({ page }) => {
    const pageErrors = await openFindingsView(page, findingsAppUrl);
    await expect(page.locator("#paiRuleSource")).toContainText("not loaded");
    await expect(page.locator('#paiRuleStats [data-rule-stat=""] .stat-value')).toHaveText("12");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1012"]')).toContainText("Outside home tenant (PowerShell)");
    expect(pageErrors).toEqual([]);
});

test("Findings view counts unclassified objects apart and lists them only on request", async ({ page }) => {
    const pageErrors = await openFindingsView(page, unclassifiedFindingsAppUrl);
    // A check affected only by unclassified objects is skipped with the reason to classify them.
    const skippedRow = page.locator('#paiRuleList tr[data-rule="EO.1003"]');
    await expect(skippedRow.locator(".pai-status")).toHaveText(/Skipped/);
    await expect(skippedRow.locator(".pai-rule-why")).toContainText("Classify these objects (EO.2001)");
    await expect(skippedRow.locator(".pai-rule-unclassified-hint")).toHaveText("+1 unclassified");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.1001"] .pai-rule-unclassified-hint')).toHaveText("+1 unclassified");

    await skippedRow.locator("[data-rule-open]").click();
    const body = page.locator("#paiRuleBody");
    await expect(body.locator(".pai-rule-unclassified")).toContainText("1 unclassified object (2 affected instances) would apply to this check.");
    await expect(body.locator("#paiRuleResultsBody")).toHaveText("No classified objects are affected.");
    await body.locator("#paiRuleShowUnclassified").check();
    await expect(body.locator("#paiRuleResultsTitle")).toHaveText("Affected objects (0 + 1 unclassified object with 2 results)");
    // The two results of the object are one row with their number, expandable to the results.
    await expect(body.locator("#paiRuleResultsBody tr.pai-rule-unclassified-row")).toHaveCount(1);
    await expect(body.locator("#paiRuleResultsBody [data-result-group-toggle]")).toHaveText("2 role assignments");
    await body.locator("#paiRuleResultsBody [data-result-group-toggle]").click();
    await expect(body.locator("#paiRuleResultsBody [data-result-group-toggle]")).toHaveAttribute("aria-expanded", "true");
    await expect(body.locator("#paiRuleResultsBody tr.pai-rres-child")).toHaveCount(2);
    await expect(body.locator("#paiRuleResultsBody")).toContainText("reaches the Tier 1 service 'Users'");
    await expect(body.locator("#paiRuleResultsBody .tier-badge").first()).toContainText("Unclassified");
    await body.locator("#paiRuleShowUnclassified").uncheck();
    await expect(body.locator("#paiRuleResultsBody tr.pai-rule-unclassified-row")).toHaveCount(0);

    // A failed check lists its classified results; the unclassified ones stay hidden until requested.
    await page.locator("#paiRuleClose").click();
    await page.locator('#paiRuleList tr[data-rule="EO.1001"] [data-rule-open]').click();
    await expect(body.locator(".pai-rule-unclassified")).toContainText("1 unclassified object would also apply to this check.");
    await expect(body.locator("#paiRuleResultsBody tr")).toHaveCount(1);
    await expect(body.locator("#paiRuleResultsBody")).toContainText("Admin A reaches a Control Plane service.");
    // The info bar links to the check that lists the unclassified objects.
    await body.locator('.pai-rule-unclassified [data-rule-open="EO.2001"]').click();
    await expect(page).toHaveURL(/#rule=EO\.2001$/);
    expect(pageErrors).toEqual([]);
});

test("Findings view uses the catalog fields and shows Error and deprecated checks", async ({ page }) => {
    const pageErrors = await openFindingsView(page, catalogFindingsAppUrl);
    // Categories in catalog order with the catalog titles.
    await expect(page.locator("#paiRuleList .eo-group-title")).toHaveText(["Workload and agent identities", "Just-in-time (catalog)", "Drift"]);
    await expect(page.locator('#paiRuleStats [data-rule-stat="Error"] .stat-value')).toHaveText("1");
    await expect(page.locator('#paiRuleStats [data-rule-stat="Excluded"] .stat-value')).toHaveText("1");
    await expect(page.locator('#paiRuleStatusPills [data-value="Error"] .eo-pill-count')).toHaveText("1");
    await expect(page.locator(".pai-status-bar .pai-bar-error")).toHaveCount(1);
    // A check without result: no counts, the reason under the title.
    const errorRow = page.locator('#paiRuleList tr[data-rule="EO.3010"]');
    await expect(errorRow.locator(".pai-status")).toHaveText(/Error/);
    await expect(errorRow.locator(".pai-rule-why")).toHaveText("The snapshot could not be read.");
    await expect(errorRow.locator(".pai-rc-affected")).not.toContainText("of");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.8099"] .pai-rule-why')).toHaveText("Deprecated: replaced by EO.8001.");
    await errorRow.locator("[data-rule-open]").click();
    await expect(page.locator("#paiRuleBody .pai-rule-reason")).toContainText("Evaluation error: The snapshot could not be read.");
    await expect(page.locator("#paiRuleBody .pai-blade-stat-value")).toHaveText(["–", "–", "–"]);
    expect(pageErrors).toEqual([]);
});

test("Privileged Assets checks of the current data format use the catalog fields and skip excluded rules", async ({ page }) => {
    const pageErrors = await openApp(page, catalogDataAppUrl);
    await expect(page.locator(`#paiTableBody tr[data-object="${userId}"] .pai-findings-cell .pai-ftop`)).toHaveText("Synchronized Control Plane identity");
    // The deprecated (Excluded) rule reports no finding.
    await expect(page.locator(`#paiTableBody tr[data-object="${groupId}"] .pai-findings-cell`)).toHaveText("None");
    await page.goto(`${catalogDataAppUrl}?view=findings`);
    await expect(page.locator("#paiRuleList .eo-group-title")).toHaveText(["Classification", "Account protection"]);
    await expect(page.locator('#paiRuleList tr[data-rule="EO.4001"] [data-rule-open]')).toHaveText("No Control Plane identity is synchronized.");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.2001"] .pai-rule-why')).toHaveText("Classification data could not be read.");
    expect(pageErrors).toEqual([]);
});

test("Findings view evaluates the Privileged Assets checks in the browser for data without findings", async ({ page }) => {
    const pageErrors = await openFindingsView(page, appUrl);
    await expect(page.locator("#paiRuleSource")).toContainText("evaluated in this browser");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.4001"]')).toContainText("Failed");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.4001"] .pai-rc-affected')).toContainText("1 object");
    await expect(page.locator('#paiRuleList tr[data-rule="EO.4001"] .pai-rc-affected')).toContainText("of 3 evaluated");
    await expect(page.locator("#paiRuleEmpty")).toBeHidden();
    expect(pageErrors).toEqual([]);
});

test("Findings view shows one empty state with the command to run when there are no check results", async ({ page }) => {
    const pageErrors = await openFindingsView(page, noRulesAppUrl);
    await expect(page.locator("#paiRuleEmpty")).toBeVisible();
    await expect(page.locator("#paiRuleEmpty")).toContainText("New-EntraOpsReportingData");
    await expect(page.locator("#paiRuleEmpty")).toContainText("Invoke-EntraOpsAssessment");
    await expect(page.locator("#paiRuleStats")).toBeHidden();
    await expect(page.locator("#secPaiRules")).toBeHidden();
    await expect(page.getByText("No check results")).toHaveCount(1);
    expect(pageErrors).toEqual([]);
});

test("Back returns from a check to the object it was opened from, and deep links open the Findings view", async ({ page }) => {
    const pageErrors = await openApp(page, savedFindingsAppUrl);
    await page.click(`#paiTableBody button[data-open="${userId}"]`);
    await expect(page).toHaveURL(new RegExp(`#asset=${userId}$`));
    await page.locator('#paiDrawerFindings [data-rule-open="EO.3001"]').click();
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page).toHaveURL(/\?view=findings#rule=EO\.3001$/);

    await page.goBack();
    await expect(page.locator("#paiRuleBlade")).not.toHaveClass(/open/);
    await expect(page.locator("#paiDrawer")).toHaveClass(/open/);
    await expect(page).toHaveURL(new RegExp(`#asset=${userId}$`));
    await expect(page.locator("#paiViewTitle")).toHaveText("Privileged Assets");

    // A check link without ?view=findings opens the Findings view; an unknown check shows a note.
    await page.goto(`${savedFindingsAppUrl}#rule=EO.3007`);
    await expect(page.locator("#paiViewTitle")).toHaveText("Findings");
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page).toHaveURL(/\?view=findings#rule=EO\.3007$/);
    await page.goto(`${savedFindingsAppUrl}?view=findings#rule=EO.9999`);
    await expect(page.locator("#paiRuleBlade")).not.toHaveClass(/open/);
    await expect(page.locator("#paiRuleNotFound")).toContainText("Check EO.9999 was not found");
    expect(pageErrors).toEqual([]);
});

test("Side panels are modal dialogs that keep and return the focus", async ({ page }) => {
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    const blade = page.locator("#paiRuleBlade");
    await expect(blade).toHaveAttribute("role", "dialog");
    await expect(blade).toHaveAttribute("aria-modal", "true");
    await expect(blade).toHaveAttribute("aria-labelledby", "paiRuleTitle");
    const opener = page.locator('#paiRuleList [data-rule-open="EO.3001"]');
    await opener.focus();
    await page.keyboard.press("Enter");
    await expect(blade).toHaveClass(/open/);
    await expect(page.locator("#paiRuleClose")).toBeFocused();
    // Tab cycles inside the blade.
    for (let i = 0; i < 25; i++) await page.keyboard.press("Tab");
    expect(await page.evaluate(() => document.getElementById("paiRuleBlade").contains(document.activeElement))).toBe(true);
    await page.keyboard.press("Shift+Tab");
    expect(await page.evaluate(() => document.getElementById("paiRuleBlade").contains(document.activeElement))).toBe(true);
    await page.keyboard.press("Escape");
    await expect(blade).not.toHaveClass(/open/);
    await expect(opener).toBeFocused();

    await page.goto(savedFindingsAppUrl);
    const objectButton = page.locator(`#paiTableBody button[data-open="${userId}"]`);
    await objectButton.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#paiDrawerClose")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(objectButton).toBeFocused();
    expect(pageErrors).toEqual([]);
});

test("Findings view names checks consistently and lists only the sections of the current view", async ({ page }) => {
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    await expect(page.locator("#secPaiRules .card-head")).toContainText("Checks");
    await expect(page.locator("#paiRuleCount")).toHaveText(/^\d+ of \d+ checks$/);
    await expect(page.locator(".nav-item.section-item:visible")).toHaveText([/Checks$/, /Exceptions$/]);
    await page.locator('#paiRuleList [data-rule-open="EO.3001"]').click();
    await expect(page.locator("#paiRuleKicker")).toHaveText("Check · Just-in-time access");
    // The Maester test is linked once; the rule ID is a label.
    await expect(page.locator("#paiRuleChips")).not.toContainText("MP.EOPS.3001");
    await expect(page.locator("#paiRuleBody")).not.toContainText("Rule details");
    await expect(page.locator('#paiRuleBody a[href*="Test.MP.EOPS.3001.md"]')).toHaveCount(1);
    await page.keyboard.press("Escape");
    await page.click('.nav-subitem[data-view-nav="overview"]');
    await expect(page.locator(".nav-item.section-item:visible")).toHaveText([/Metrics$/, /Inventory$/]);
    expect(pageErrors).toEqual([]);
});

test("phone layout stacks the checks and keeps the Findings view inside the viewport", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    const row = page.locator('#paiRuleList tr[data-rule="EO.3001"]');
    const width = await row.locator(".pai-rc-check").evaluate((cell) => cell.getBoundingClientRect().width);
    expect(width).toBeGreaterThan(250);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    // The blade lists the affected objects with the type under the name and the tier on one line.
    await row.locator("[data-rule-open]").click();
    const badge = page.locator("#paiRuleResultsBody .tier-badge").first();
    expect(await badge.evaluate((element) => element.getClientRects().length)).toBe(1);

    // Inventory: findings summary under the object name, no Findings column.
    await page.goto(savedFindingsAppUrl);
    await expect(page.locator(`#paiTableBody tr[data-object="${userId}"] .pai-fmini`)).toBeVisible();
    await expect(page.locator("th.pai-col-findings")).toBeHidden();
    expect(pageErrors).toEqual([]);
});

test("check panel keeps the tier and links of an affected object inside their cells", async ({ page }) => {
    await page.setViewportSize({ width: 1480, height: 900 });
    const pageErrors = await openFindingsView(page, exceptionFindingsAppUrl);
    await page.locator('#paiRuleList [data-rule-open="EO.1001"]').click();
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page.locator("#paiRuleBody table.pai-rule-results thead th")).toHaveText(["Object and tier", "Details", "Exception"]);
    const escapes = await page.locator("#paiRuleResultsBody td").evaluateAll((cells) => cells.flatMap((cell) => {
        const box = cell.getBoundingClientRect();
        return [...cell.querySelectorAll(".tier-badge, .pai-result-links a, button")].filter((element) => {
            const rect = element.getBoundingClientRect();
            return rect.width && (rect.left < box.left - 1 || rect.right > box.right + 1);
        }).map((element) => element.textContent.trim());
    }));
    expect(escapes).toEqual([]);
    // The cells are top-aligned: the object name starts on the line of the message.
    const tops = await page.locator("#paiRuleResultsBody tr").first().locator("td").evaluateAll((cells) => cells.map((cell) => getComputedStyle(cell).verticalAlign));
    expect(new Set(tops)).toEqual(new Set(["top"]));
    expect(pageErrors).toEqual([]);
});

test("Findings view uses the standard status and severity colors", async ({ page }) => {
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    const color = (selector, property = "color") => page.locator(selector).first().evaluate((element, name) => getComputedStyle(element)[name], property);
    // Failed red and Passed green, like the fail / ok status of the other EntraOps reports.
    expect(await color("#paiRuleList .pai-status-failed")).toBe("rgb(164, 38, 44)");
    expect(await color("#paiRuleList .pai-status-passed")).toBe("rgb(14, 112, 14)");
    // Critical dark red (solid), High red, Medium orange.
    expect(await color("#paiRuleList .pai-sev.sev-critical", "backgroundColor")).toBe("rgb(117, 11, 28)");
    expect(await color("#paiRuleList .pai-sev.sev-high")).toBe("rgb(179, 38, 43)");
    expect(await color("#paiRuleList .pai-sev.sev-medium")).toBe("rgb(168, 67, 11)");
    expect(pageErrors).toEqual([]);
});

test("inventory table fits its card although a finding title is long", async ({ page }) => {
    await page.setViewportSize({ width: 1600, height: 900 });
    const pageErrors = await openFindingsView(page, savedFindingsAppUrl);
    await page.click('.nav-subitem[data-view-nav="overview"]');
    await page.locator("#paiTableBody .pai-ftop").first().evaluate((element) => { element.textContent = "A very long finding title ".repeat(12); });
    const fit = await page.locator("#paiTable").evaluate((table) => table.scrollWidth - table.parentElement.clientWidth);
    expect(fit).toBeLessThanOrEqual(1);
    expect(pageErrors).toEqual([]);
});

test("finding links to the EAM Dashboard and Access Path Map only for objects of the Privileged EAM data", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${outsideFindingsAppUrl}?view=findings#rule=EO.6003`);
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page.locator(`#paiRuleResultsBody a[href="../EamDashboard/index.html#asset=${groupId}"]`)).toHaveCount(1);
    await expect(page.locator("#paiRuleResultsBody")).toContainText("abababab-abab-abab-abab-abababababab");
    await expect(page.locator('#paiRuleResultsBody a[href*="abababab-abab-abab-abab-abababababab"]')).toHaveCount(0);
    expect(pageErrors).toEqual([]);
});

test("asset deep link to an object outside the inventory shows a notice", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${appUrl}#asset=88888888-8888-8888-8888-888888888888`);
    await expect(page.locator("#eoDeepLinkNotice")).toBeVisible();
    await expect(page.locator("#eoDeepLinkNotice")).toContainText("Privileged asset 88888888-8888-8888-8888-888888888888 was not found in the privileged assets.");
    expect(pageErrors).toEqual([]);
});

// ---- Check panel: objects and results, notes, evidence, bulk and reconciled exceptions ---------------------------
// Pending exception changes are stored per tenant (the fixtures are tenant "t1"); v1 was one key for all tenants.
const legacyExceptionStoreKey = "entraops.privilegedAssets.findingExceptions.v1";
const exceptionStoreKey = "entraops.privilegedAssets.findingExceptions.v2.t1";

async function captureDownloads(page) {
    await page.evaluate(() => {
        window.__downloads = [];
        const createObjectURL = URL.createObjectURL;
        URL.createObjectURL = (blob) => { blob.text().then((text) => window.__downloads.push(text)); return createObjectURL(blob); };
    });
}

test("check panel groups the results by object and counts objects and results", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    const row = page.locator('#paiRuleList tr[data-rule="EO.1001"]');
    await expect(row.locator(".pai-rc-affected")).toContainText("2 objects");
    await expect(row.locator(".pai-rc-results")).toHaveText("3 results · of 3 evaluated");
    // A note of an evaluated check is shown in the list and in its panel.
    await expect(row.locator(".pai-rule-why")).toHaveText("Note: 2 excluded groups could not be resolved.");
    await row.locator("[data-rule-open]").click();
    const body = page.locator("#paiRuleBody");
    await expect(body.locator(".pai-rule-note")).toHaveText("Note: 2 excluded groups could not be resolved.");
    await expect(body.locator(".pai-blade-stat-label")).toHaveText(["Affected objects", "Results", "Evaluated"]);
    await expect(body.locator(".pai-blade-stat-value")).toHaveText(["2", "3", "3"]);
    await expect(body.locator("#paiRuleResultsTitle")).toHaveText("Affected objects (2 objects · 3 results)");
    // The two results of Admin A are one row with their number and the first message; App B has one row.
    const group = body.locator("#paiRuleResultsBody tr.pai-rgroup");
    await expect(group).toHaveCount(1);
    await expect(group.locator("[data-result-group-toggle]")).toHaveText("2 role assignments");
    await expect(group.locator(".pai-rgroup-preview")).toHaveText("Admin A reaches Billing at path a.");
    await expect(body.locator("#paiRuleResultsBody tr.pai-rres-child")).toHaveCount(0);
    await group.locator("[data-result-group-toggle]").click();
    await expect(body.locator("#paiRuleResultsBody tr.pai-rres-child")).toHaveCount(2);
    await expect(body.locator('#paiRuleResultsBody [data-result-group-toggle]')).toBeFocused();
    // The search filters the results: one result of the object is left, shown as a row of its own.
    await page.fill("#paiRuleResultSearch", "path b");
    await expect(body.locator("#paiRuleResultsBody tr")).toHaveCount(1);
    await expect(body.locator("#paiRuleResultsBody")).toContainText("Admin A reaches Billing at path b.");
    expect(pageErrors).toEqual([]);
});

test("skipped checks tell not applicable apart, and results outside the inventory show their tier name", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await expect(page.locator('#paiRuleList tr[data-rule="EO.3012"] .pai-rule-why')).toHaveText("Not applicable: Nothing in scope.");
    await page.locator('#paiRuleList tr[data-rule="EO.3012"] [data-rule-open]').click();
    await expect(page.locator("#paiRuleBody .pai-rule-reason")).toHaveText("Not applicable: Nothing in scope.");
    await page.keyboard.press("Escape");
    // AdminTierLevel 2 of an unclassified object is not "User Access": the tier name of the result decides.
    await page.locator('#paiRuleList tr[data-rule="EO.4003"] [data-rule-open]').click();
    await expect(page.locator("#paiRuleResultsBody .tier-badge")).toHaveText("Unclassified");
    expect(pageErrors).toEqual([]);
});

test("evidence shows readable labels and values, tables for lists of objects and internal IDs apart", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await page.locator('#paiRuleList tr[data-rule="EO.1001"] [data-rule-open]').click();
    await page.locator("#paiRuleResultsBody [data-result-group-toggle]").click();
    const evidence = page.locator('#paiRuleResultsBody tr[data-result="path-a"] details.pai-evidence:not(.pai-evidence-technical)');
    await evidence.locator(":scope > summary").click();
    await expect(evidence.locator(":scope > summary")).toHaveText("Evidence (7)");
    // Service repeats the first of Services, Count the total and MoreExamples=false says nothing: left out.
    await expect(evidence.locator(":scope > dl > dt")).toHaveText(["Role", "Services", "Service tier", "PIM assignment type", "Maximum activation", "Examples", "Members without access package"]);
    await expect(evidence.locator(":scope > dl > dd").nth(2)).toHaveText("Control Plane (Tier 0)");
    await expect(evidence.locator(":scope > dl > dd").nth(4)).toHaveText("8 hours");
    await expect(evidence.locator(".pai-evidence-table th")).toHaveText(["Identity", "Assigned role"]);
    await expect(evidence.locator(".pai-evidence-table td")).toHaveText(["guest@contoso.com", "Member"]);
    const technical = evidence.locator(".pai-evidence-technical");
    await expect(technical.locator("summary")).toHaveText("Technical details (2)");
    await expect(technical.locator("dt")).toHaveText(["Snapshot key", "Path IDs"]);
    expect(pageErrors).toEqual([]);
});

test("bulk exceptions accept the selected findings with one form; dismissed findings need no expiry", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await page.locator('#paiRuleList tr[data-rule="EO.1001"] [data-rule-open]').click();
    const body = page.locator("#paiRuleBody");
    await expect(body.locator("#paiRuleBulkBar")).toBeVisible();
    await expect(body.locator("[data-bulk-accept]")).toBeDisabled();
    // The checkbox of the object selects its findings (the one with an expired exception too).
    await body.locator("#paiRuleResultsBody [data-select-group]").check();
    await expect(body.locator("#paiRuleBulkCount")).toHaveText("2 selected (1 object)");
    await body.locator("[data-bulk-accept]").click();
    const form = body.locator("#paiBulkAcceptForm");
    await expect(form.locator(".pai-accept-title")).toHaveText("Accept 2 selected findings");
    await expect(form.locator('input[name="ExpiresOn"]')).not.toHaveValue("");
    await form.locator('select[name="State"]').selectOption("Dismissed");
    await expect(form.locator('input[name="ExpiresOn"]')).toHaveValue("");
    await expect(form.locator("[data-expires-label]")).toHaveText("Expires on (optional)");
    await form.locator('button[type="submit"]').click();
    await expect(form.locator(".pai-accept-error")).toHaveText("Enter a justification.");
    await form.locator('textarea[name="Justification"]').fill("Test accounts");
    await form.locator('button[type="submit"]').click();
    await expect(body.locator("#paiBulkAcceptForm")).toHaveCount(0);
    await expect(page.locator("#paiExceptionMeta")).toHaveText("2 exceptions · 2 pending changes");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-a|"] .status-chip')).toHaveText("Changed");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-b|"] .status-chip')).toHaveText("Added");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-b|"]')).toContainText("Dismissed");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-b|"] td').nth(3)).toHaveText("-");
    expect(pageErrors).toEqual([]);
});

test("a new object exception shows on a finding whose own exception expired, like the evaluation picks it", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await page.locator('#paiRuleList tr[data-rule="EO.1001"] [data-rule-open]').click();
    const body = page.locator("#paiRuleBody");
    await body.locator("#paiRuleResultsBody [data-result-group-toggle]").click();
    const pathA = body.locator('#paiRuleResultsBody tr[data-result="path-a"]');
    await expect(pathA).toContainText("Expired");
    await pathA.locator("[data-accept]").click();
    const form = body.locator("#paiAcceptForm");
    await form.locator('input[value="object"]').check();
    await form.locator('textarea[name="Justification"]').fill("Migration");
    await form.locator('button[type="submit"]').click();
    // The object exception applies to both findings of Admin A, the expired one included, with Undo.
    await expect(pathA).toContainText("Pending - export the file");
    await expect(pathA.locator(`[data-exception-remove="eo.1001||${userId}"]`)).toHaveCount(1);
    await expect(body.locator('#paiRuleResultsBody tr[data-result="path-b"]')).toContainText("Pending - export the file");
    expect(pageErrors).toEqual([]);
});

test("local exception changes the file already has are dropped, and a changed file is flagged", async ({ page }) => {
    const fileEntry = { RuleId: "EO.1001", InstanceId: "path-a", ObjectId: userId, DisplayName: "Admin A", State: "RiskAccepted", Justification: "Old", AcceptedBy: "x", AcceptedOn: "2019-10-01", ExpiresOn: "2020-01-01", Reference: "" };
    const changedStore = { tenant: "t1", baseFingerprint: "0-old", upserts: { "eo.1001|path-a|": { ...fileEntry, Justification: "Renewed locally", ExpiresOn: "2099-01-01", AcceptedOn: "2098-12-01" } }, removals: [] };
    // Each store is seeded by the document that reads it, before the app runs: a write from the test right before
    // a navigation is not reliably visible to the next file:// document on slow runners.
    await page.addInitScript(([key, initial, changed]) => localStorage.setItem(key, new URLSearchParams(location.search).has("fileChanged") ? changed : initial),
        [legacyExceptionStoreKey, JSON.stringify({ tenant: "t1", upserts: { "eo.1001|path-a|": fileEntry }, removals: ["eo.1001||gone"] }), JSON.stringify(changedStore)]);
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await expect(page.locator("#paiExceptionMeta")).toHaveText("1 exceptions · 0 pending changes");
    // The v1 entry is read once and removed.
    expect(await page.evaluate((key) => localStorage.getItem(key), legacyExceptionStoreKey)).toBeNull();
    expect(await page.evaluate((key) => localStorage.getItem(key), exceptionStoreKey)).toBeNull();
    await expect(page.locator("#paiExceptionFileChanged")).toBeHidden();

    // A pending change made on another version of the file: flagged until it is kept or discarded.
    await page.goto(`${groupedFindingsAppUrl}?view=findings&fileChanged`);
    await expect(page.locator("#paiExceptionFileChanged")).toBeVisible();
    // Until then the entry of the file is shown, not the change of this browser.
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-a|"] .status-chip')).toHaveText("Expired");
    await page.click("#paiExceptionFileChangedKeep");
    await expect(page.locator("#paiExceptionFileChanged")).toBeHidden();
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-a|"] .status-chip')).toHaveText("Changed");
    const stored = JSON.parse(await page.evaluate((key) => localStorage.getItem(key), exceptionStoreKey));
    expect(stored.baseFingerprint).not.toBe("0-old");
    expect(pageErrors).toEqual([]);
});

test("exception import rejects impossible dates and shortens a risk accepted for longer than MaxDays", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    const rows = [
        { RuleId: "EO.1001", ObjectId: userId, State: "RiskAccepted", Justification: "j", AcceptedOn: "2026-13-45", ExpiresOn: "2027-01-01" },
        { RuleId: "EO.1001", InstanceId: "path-c", ObjectId: servicePrincipalId, State: "RiskAccepted", Justification: "j", AcceptedOn: "2026-01-01", ExpiresOn: "2026-12-31" }
    ];
    await page.setInputFiles("#paiExceptionImport", { name: "FindingExceptions.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(rows)) });
    const result = page.locator("#paiExceptionImportResult");
    await expect(result).toContainText("Imported 1 exceptions from FindingExceptions.json. Rejected 1 entries. 1 entries were adjusted or need attention.");
    await expect(result).toContainText("AcceptedOn must be a date (yyyy-mm-dd)");
    await expect(result).toContainText("shortened to 2026-04-01");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-c|"]')).toContainText("2026-04-01");
    expect(pageErrors).toEqual([]);
});

test("tiles say what they count and the object panel shows the saved Privileged Assets results", async ({ page }) => {
    const pageErrors = await openApp(page, savedFindingsAppUrl);
    await expect(page.locator('#paiStats [data-stat="0"] .stat-sub')).toContainText("Unclassified:");
    await expect(page.locator('#paiStats [data-stat="1"] .stat-sub')).toContainText("by most severe finding");
    await expect(page.locator('#paiStats [data-stat="1"]')).toHaveAttribute("title", /most severe finding/);
    // Outside What-if the panel of an object shows the message of the saved Privileged Assets result.
    await page.click(`#paiTableBody button[data-open="${servicePrincipalId}"]`);
    await expect(page.locator("#paiDrawerFindings")).toContainText("Shown from the data file.");
    await page.keyboard.press("Escape");
    await page.click('.nav-subitem[data-view-nav="findings"]');
    await expect(page.locator('#paiRuleStats [data-rule-stat="Failed"] .stat-sub')).toHaveText(/ checks?$/);
    expect(pageErrors).toEqual([]);
});

test("check deep links ignore the casing and an unknown check is reported also without checks", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${groupedFindingsAppUrl}?view=findings#rule=eo.1001`);
    await expect(page.locator("#paiRuleBlade")).toHaveClass(/open/);
    await expect(page.locator("#paiRuleChips .pai-rule-id")).toHaveText("EO.1001");
    await page.goto(`${noRulesAppUrl}?view=findings#rule=EO.9999`);
    await expect(page.locator("#paiRuleNotFound")).toBeVisible();
    await expect(page.locator("#paiRuleNotFound")).toContainText("EO.9999");
    expect(pageErrors).toEqual([]);
});

test("inventory CSV names the tiers and the most severe finding of EntraOps and Maester", async ({ page }) => {
    const pageErrors = await openApp(page, savedFindingsAppUrl);
    await captureDownloads(page);
    await page.click("#paiExportInventory");
    await expect.poll(() => page.evaluate(() => window.__downloads.length)).toBe(1);
    const lines = (await page.evaluate(() => window.__downloads[0])).trim().split(/\r?\n/).map((line) => line.split('","').map((cell) => cell.replace(/^"|"$/g, "")));
    const header = lines[0];
    const app = lines.find((line) => line[0] === servicePrincipalId);
    expect(["Control Plane", "Management Plane", "Workload Plane", "User Access", "Unclassified"]).toContain(app[header.indexOf("ObjectTier")]);
    expect(app[header.indexOf("HighestSeverity")]).toBe("Critical");
    expect(pageErrors).toEqual([]);
});

// ---- Expired acceptance, unresolved file conflict, pending changes per tenant, prototype-member keys ---------------
test("the side panel of an object lists its findings whose exception has expired", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${expiredFindingsAppUrl}#asset=${groupId}`);
    const section = page.locator("#paiDrawerExpired");
    await expect(section).toBeVisible();
    await expect(section.locator("summary")).toHaveText("Exception expired (1)");
    await expect(section).toContainText("EO.1004");
    await expect(section.locator(".pai-exception-expired")).toHaveText("Exception expired 2020-01-15");
    await expect(section).toContainText("These findings count again at the next evaluation.");
    // An object without such a finding has no section.
    await page.goto(`${expiredFindingsAppUrl}#asset=${servicePrincipalId}`);
    await expect(page.locator("#paiDrawer")).toBeVisible();
    await expect(page.locator("#paiDrawerExpired")).toHaveCount(0);
    expect(pageErrors).toEqual([]);
});

test("a finding whose exception has expired is not shown as accepted, and its check says that the results are outdated", async ({ page }) => {
    const pageErrors = await openFindingsView(page, expiredFindingsAppUrl);
    // The saved status stays, but not as "Risk accepted": the row says that it is from the last evaluation.
    const passed = page.locator('#paiRuleList tr[data-rule="EO.1004"]');
    await expect(passed.locator(".pai-status")).toHaveText(/Passed/);
    await expect(passed.locator(".pai-rule-risk-chip")).toHaveCount(0);
    await expect(passed.locator(".pai-rule-expired-chip")).toHaveText("Exception expired");
    await expect(passed.locator(".pai-rule-accepted-hint")).toHaveCount(0);
    await expect(passed.locator(".pai-rule-expired-hint")).toHaveText("+1 exception expired");
    await expect(passed.locator(".pai-rule-stale")).toContainText("1 exception expired (2020-01-15) since the last evaluation");
    await expect(passed.locator(".pai-rule-stale")).toContainText('The status "Passed" and the counts are from the last evaluation - run New-EntraOpsReportingData to regenerate the report data.');
    // An active exception of the same check is still counted as risk accepted, the expired one apart.
    const failed = page.locator('#paiRuleList tr[data-rule="EO.1001"]');
    await expect(failed.locator(".pai-rule-accepted-hint")).toHaveText("+1 risk accepted");
    await expect(failed.locator(".pai-rule-expired-hint")).toHaveText("+1 exception expired");

    // The panel: no "accepted findings" bar, a notice, and the finding in the list without "Show accepted findings".
    await passed.locator("[data-rule-open]").click();
    const body = page.locator("#paiRuleBody");
    await expect(page.locator("#paiRuleChips .pai-rule-risk-chip")).toHaveCount(0);
    await expect(page.locator("#paiRuleChips .pai-rule-expired-chip")).toHaveText("Exception expired");
    await expect(body.locator(".pai-rule-accepted")).toHaveCount(0);
    await expect(body.locator(".pai-rule-expired")).toContainText("Results of the last evaluation.");
    await expect(body.locator(".pai-rule-expired")).toContainText("regenerate the report data");
    await expect(page.locator("#paiRuleResultsTitle")).toContainText("+ 1 with an expired exception");
    const row = body.locator('#paiRuleResultsBody tr[data-result="g1"]');
    await expect(row).toHaveClass(/pai-rule-expired-row/);
    await expect(row).not.toHaveClass(/pai-rule-accepted-row/);
    await expect(row.locator(".pai-exception-expired")).toHaveText("Exception expired 2020-01-15");
    await expect(row.locator(".pai-exception-riskaccepted")).toHaveCount(0);
    // It can be accepted again, like an open finding.
    await row.locator("[data-accept]").click();
    await body.locator('#paiAcceptForm textarea[name="Justification"]').fill("Renewed");
    await body.locator('#paiAcceptForm button[type="submit"]').click();
    await expect(row).toContainText("Pending - export the file");
    await page.keyboard.press("Escape");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1004|g1|"] .status-chip')).toHaveText("Changed");

    // The other check lists the active acceptance only on request, the expired one always.
    await failed.locator("[data-rule-open]").click();
    await expect(body.locator(".pai-rule-accepted")).toContainText("1 accepted finding (1 risk accepted)");
    await expect(body.locator('#paiRuleResultsBody tr[data-result="path3"] .pai-exception-expired')).toHaveText("Exception expired 2020-01-15");
    await expect(body.locator('#paiRuleResultsBody tr[data-result="path2"]')).toHaveCount(0);
    await body.locator("#paiRuleShowAccepted").check();
    await expect(body.locator('#paiRuleResultsBody tr[data-result="path2"]')).toHaveClass(/pai-rule-accepted-row/);
    expect(pageErrors).toEqual([]);
});

test("an unresolved change of the exceptions file is not acknowledged by other edits: the file wins and the export waits", async ({ page }) => {
    const fileEntry = { RuleId: "EO.1001", InstanceId: "path-a", ObjectId: userId, DisplayName: "Admin A", State: "RiskAccepted", Justification: "Old", AcceptedBy: "x", AcceptedOn: "2019-10-01", ExpiresOn: "2020-01-01", Reference: "" };
    const stale = { tenant: "t1", baseFingerprint: "0-old", upserts: { "eo.1001|path-a|": { ...fileEntry, Justification: "Renewed locally", ExpiresOn: "2099-01-01", AcceptedOn: "2098-12-01" } }, removals: [] };
    await page.addInitScript(([key, value]) => { if (!sessionStorage.getItem("seeded")) { localStorage.setItem(key, value); sessionStorage.setItem("seeded", "1"); } }, [exceptionStoreKey, JSON.stringify(stale)]);
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await captureDownloads(page);
    const banner = page.locator("#paiExceptionFileChanged");
    const pathA = page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-a|"]');
    await expect(banner).toBeVisible();
    await expect(banner.locator("#paiExceptionFileChangedList li")).toHaveText(["Change EO.1001 · Admin A (Risk accepted until 2099-01-01)"]);
    // The entry of the file is shown, not the stale change of this browser.
    await expect(pathA.locator(".status-chip")).toHaveText("Expired");
    await expect(pathA).toContainText("Old");
    await expect(pathA).not.toContainText("Renewed locally");
    await expect(page.locator("#paiExceptionMeta")).toHaveText("1 exceptions · 0 pending changes · 1 not applied");
    await expect(page.locator("#paiExceptionExport")).toBeDisabled();

    // Another edit while the notice shows keeps the stored fingerprint and the change that is held back.
    const added = { RuleId: "EO.1001", InstanceId: "path-c", ObjectId: servicePrincipalId, State: "Dismissed", Justification: "False positive" };
    await page.setInputFiles("#paiExceptionImport", { name: "FindingExceptions.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify([added])) });
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-c|"] .status-chip')).toHaveText("Added");
    let stored = JSON.parse(await page.evaluate((key) => localStorage.getItem(key), exceptionStoreKey));
    expect(stored.baseFingerprint).toBe("0-old");
    expect(Object.keys(stored.upserts).sort()).toEqual(["eo.1001|path-a|", "eo.1001|path-c|"]);
    expect(stored.upserts["eo.1001|path-a|"].Justification).toBe("Renewed locally");
    await expect(page.locator("#paiExceptionExport")).toBeDisabled();
    await page.evaluate(() => document.getElementById("paiExceptionExport").dispatchEvent(new MouseEvent("click", { bubbles: true })));

    // After a reload the notice is still there, and nothing was exported.
    await page.reload();
    await captureDownloads(page);
    await expect(banner).toBeVisible();
    await expect(pathA.locator(".status-chip")).toHaveText("Expired");
    await expect(page.locator("#paiExceptionExport")).toBeDisabled();

    // Keep: the changes apply on the current file, and the export works again.
    await page.click("#paiExceptionFileChangedKeep");
    await expect(banner).toBeHidden();
    await expect(pathA.locator(".status-chip")).toHaveText("Changed");
    await expect(pathA).toContainText("Renewed locally");
    await expect(page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-c|"] .status-chip')).toHaveText("Added");
    stored = JSON.parse(await page.evaluate((key) => localStorage.getItem(key), exceptionStoreKey));
    expect(stored.baseFingerprint).not.toBe("0-old");
    await expect(page.locator("#paiExceptionExport")).toBeEnabled();
    await page.click("#paiExceptionExport");
    await expect.poll(() => page.evaluate(() => window.__downloads.length)).toBe(1);
    const exported = JSON.parse(await page.evaluate(() => window.__downloads[0]));
    expect(exported.map((entry) => entry.InstanceId + " " + entry.Justification).sort()).toEqual(["path-a Renewed locally", "path-c False positive"]);

    // Discard also drops the changes that are held back.
    await page.evaluate(([key, value]) => localStorage.setItem(key, value), [exceptionStoreKey, JSON.stringify(stale)]);
    await page.reload();
    await expect(banner).toBeVisible();
    page.once("dialog", (dialog) => dialog.accept());
    await page.click("#paiExceptionFileChangedDiscard");
    await expect(banner).toBeHidden();
    await expect(page.locator("#paiExceptionMeta")).toHaveText("1 exceptions · 0 pending changes");
    expect(await page.evaluate((key) => localStorage.getItem(key), exceptionStoreKey)).toBeNull();
    expect(pageErrors).toEqual([]);
});

test("pending exception changes of another tenant are kept when this tenant is edited", async ({ page }) => {
    const otherTenant = { tenant: "fabrikam.onmicrosoft.com", baseFingerprint: "0-811c9dc5", upserts: { "eo.3001||99999999-9999-9999-9999-999999999999": { RuleId: "EO.3001", ObjectId: "99999999-9999-9999-9999-999999999999", State: "Dismissed", Justification: "Fabrikam break glass" } }, removals: [] };
    const otherKey = "entraops.privilegedAssets.findingExceptions.v2.fabrikam.onmicrosoft.com";
    // Stored by the previous version, under the one key of all tenants.
    await page.addInitScript(([key, value]) => { if (!sessionStorage.getItem("seeded")) { localStorage.setItem(key, value); sessionStorage.setItem("seeded", "1"); } }, [legacyExceptionStoreKey, JSON.stringify(otherTenant)]);
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    await expect(page.locator("#paiExceptionMeta")).toHaveText("1 exceptions · 0 pending changes");
    const added = { RuleId: "EO.1001", InstanceId: "path-c", ObjectId: servicePrincipalId, State: "Dismissed", Justification: "False positive" };
    await page.setInputFiles("#paiExceptionImport", { name: "FindingExceptions.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify([added])) });
    await expect(page.locator("#paiExceptionMeta")).toHaveText("2 exceptions · 1 pending changes");
    const storage = await page.evaluate(([legacy, own, other]) => [localStorage.getItem(legacy), localStorage.getItem(own), localStorage.getItem(other)], [legacyExceptionStoreKey, exceptionStoreKey, otherKey]);
    expect(storage[0]).toBeNull();
    expect(Object.keys(JSON.parse(storage[1]).upserts)).toEqual(["eo.1001|path-c|"]);
    expect(JSON.parse(storage[2])).toEqual(otherTenant);
    // A later edit and a reload leave the changes of the other tenant alone, too.
    await page.reload();
    await page.locator('#paiExceptionBody tr[data-exception="eo.1001|path-c|"] [data-exception-remove]').click();
    await expect(page.locator("#paiExceptionMeta")).toHaveText("1 exceptions · 0 pending changes");
    expect(JSON.parse(await page.evaluate((key) => localStorage.getItem(key), otherKey))).toEqual(otherTenant);
    expect(pageErrors).toEqual([]);
});

test("deep links named like members of Object.prototype show the not-found notice", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
        await page.goto("about:blank");
        await page.goto(`${groupedFindingsAppUrl}?view=findings#rule=${name}`);
        await expect(page.locator("#paiRuleNotFound")).toBeVisible();
        await expect(page.locator("#paiRuleNotFound")).toHaveText(`Check ${name} was not found in the loaded results.`);
        await expect(page.locator("#paiRuleBlade")).not.toHaveClass(/open/);
        await page.goto("about:blank");
        await page.goto(`${appUrl}#asset=${name}`);
        await expect(page.locator("#eoDeepLinkNotice")).toContainText(`Privileged asset ${name} was not found in the privileged assets.`);
        await expect(page.locator("#paiDrawer")).not.toHaveClass(/open/);
    }
    expect(pageErrors).toEqual([]);
});

test("exception import notes an expiry before the acceptance and an acceptance in the future", async ({ page }) => {
    const pageErrors = await openFindingsView(page, groupedFindingsAppUrl);
    const future = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    const rows = [
        { RuleId: "EO.1001", InstanceId: "path-b", ObjectId: userId, State: "Dismissed", Justification: "j", AcceptedOn: "2026-03-01", ExpiresOn: "2026-02-01" },
        { RuleId: "EO.1001", InstanceId: "path-c", ObjectId: servicePrincipalId, State: "Dismissed", Justification: "j", AcceptedOn: future }
    ];
    await page.setInputFiles("#paiExceptionImport", { name: "FindingExceptions.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(rows)) });
    const result = page.locator("#paiExceptionImportResult");
    await expect(result).toContainText("Imported 2 exceptions from FindingExceptions.json. 2 entries were adjusted or need attention.");
    await expect(result).toContainText("Entry 1 (EO.1001): expires on 2026-02-01, before it was accepted on 2026-03-01. Check the dates.");
    await expect(result).toContainText(`Entry 2 (EO.1001): was accepted on ${future}, a date in the future. Check the date.`);
    await expect(page.locator("#paiExceptionBody tr")).toHaveCount(3);
    expect(pageErrors).toEqual([]);
});
