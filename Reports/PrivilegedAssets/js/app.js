/*
 * EntraOps Privileged Assets
 *
 * Object-centric view of privileged objects from window.ENTRAOPS_PRIVILEGED_ASSETS_DATA
 * (New-EntraOpsPrivilegedAssetsData) with the findings of all EntraOps finding rules that concern these objects
 * (window.ENTRAOPS_FINDINGS, Save-EntraOpsFindingJson) and three views: Overview (metrics and inventory), Findings
 * (?view=findings: the results of the checks by category with remediation action, effort and user impact) and Object
 * Classification (?view=classification: worklist and PowerShell script). Role assignment details link
 * to the EAM Dashboard (#assignment= / #asset=) and objects to the Access Path Map (#node=). The worklist
 * is kept in localStorage, can be imported/exported as CSV or JSON, and - depending on the configured
 * classification method - is downloadable as the Object Classification File or feeds the PowerShell
 * script generator for custom security attributes.
 */
(function () {
    "use strict";

    var DATA = window.ENTRAOPS_PRIVILEGED_ASSETS_DATA || null;
    // Classification sources can be combined: file entry, then enabled filters, then custom security attributes.
    var SETTINGS = (DATA || {}).classificationSettings || {};
    var FILE_ENABLED = (SETTINGS.objectClassificationFile || {}).enabled === true;
    var CSA_ENABLED_FOR = (SETTINGS.customSecurityAttributes || {}).enabledFor || {};
    var CSA_ENABLED = Object.keys(CSA_ENABLED_FOR).some(function (type) { return CSA_ENABLED_FOR[type] === true; });
    var ALTERNATE_ENABLED = SETTINGS.alternateObjectTierLevelAttributes || {};
    var ALTERNATE_TYPE_LABELS = [["user", "users"], ["servicePrincipal", "service principals"], ["group", "groups"]]
        .filter(function (type) { return ALTERNATE_ENABLED[type[0]] === true; })
        .map(function (type) { return type[1]; });
    var TIERS = ["ControlPlane", "ManagementPlane", "WorkloadPlane", "UserAccess"];
    var TIER_LABEL = { ControlPlane: "Control Plane", ManagementPlane: "Management Plane", WorkloadPlane: "Workload Plane", UserAccess: "User Access", Unclassified: "Unclassified" };
    var TIER_TAG = { ControlPlane: "0", ManagementPlane: "1", WorkloadPlane: "1", UserAccess: "2" };
    var TIER_ORDER = { ControlPlane: 0, ManagementPlane: 1, WorkloadPlane: 2, UserAccess: 3, Unclassified: 4 };
    var OBJECT_TYPES = ["user", "group", "serviceprincipal", "application"];
    var TYPE_LABEL = { user: "User", group: "Group", serviceprincipal: "Service principal", application: "Application" };
    // Display names of the object types of findings that aren't in the inventory (roles, policies, the tenant).
    var OTHER_TYPE_LABEL = {
        tenant: "Tenant", administrativeunit: "Administrative unit", roledefinition: "Role definition", rolesetting: "Role setting",
        conditionalaccesspolicy: "Conditional Access policy", accesspackageassignmentpolicy: "Access package assignment policy"
    };
    // "group", "Group", "servicePrincipal" or "roleSetting" -> "Group", "Service principal", "Role setting": one casing for every type.
    function typeLabel(type) {
        if (type == null || type === "") return "";
        var key = String(type).toLowerCase();
        if (TYPE_LABEL[key] || OTHER_TYPE_LABEL[key]) return TYPE_LABEL[key] || OTHER_TYPE_LABEL[key];
        var words = String(type).replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
        return words.charAt(0).toUpperCase() + words.slice(1);
    }
    var TYPE_PLURAL = { user: "Users", group: "Groups", serviceprincipal: "Service principals", application: "Applications" };
    var TYPE_ICON = {
        user: '<path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm-5 6c0-2.5 2.2-4.5 5-4.5s5 2 5 4.5" />',
        group: '<path d="M5.5 7.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Zm5.5 0a2 2 0 1 0 0-4M1.5 13.5c0-2.2 1.8-4 4-4s4 1.8 4 4M11 9.5c2 0 3.5 1.6 3.5 4" />',
        serviceprincipal: '<path d="M2.5 3.5h11v9h-11zM5 7l1.5 1.5L5 10M8.5 10H11" />',
        application: '<path d="M2.5 2.5h4v4h-4zM9.5 2.5h4v4h-4zM2.5 9.5h4v4h-4zM9.5 9.5h4v4h-4z" />'
    };
    // Finding severities of the rule catalog (Get-EntraOpsFindingRule), most severe first. Maester tests use the same scale.
    var SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
    var SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    // Source of the findings of the other rules (Area of the rule) with the report that shows its details.
    var AREA_INFO = {
        PrivilegedAssets: { label: "Privileged Assets" },
        PrivilegedEAM: { label: "Privileged EAM", report: "EAM Dashboard", href: function (object) { return "../EamDashboard/index.html#asset=" + encodeURIComponent(object.objectId); } },
        TierBreach: { label: "Tier Breach Analyzer", report: "Tier Breach Analyzer", href: function () { return "../TierBreachAnalyzer/index.html"; } },
        PrivilegeHistory: { label: "Privilege History", report: "Privilege History", href: function () { return "../PrivilegeHistory/index.html"; } },
        AccessPackageFlow: { label: "Access Package Flow", report: "Access Package Flow", href: function () { return "../AccessPackageFlow/index.html"; } },
        PimRequestFlow: { label: "PIM Request Flow", report: "PIM Request Flow", href: function () { return "../PimRequestFlow/index.html"; } },
        TenantGovernance: { label: "Tenant Governance", report: "Configuration Analyzer", href: function () { return "../ConfigurationAnalyzer/index.html"; } }
    };
    var MAX_RESULT_MESSAGES = 5;

    // Deep links of a finding result to the affected object in the report that shows it: the PIM role setting
    // (#flow=), the access package policy (#flow=), the Conditional Access policy (#flow=), the tier breach path
    // (#sel=), the role assignment and principal in the EAM Dashboard (#assignment=, #asset=), the access path
    // (#node=) or the Tenant Governance resource (#object=). Most specific first.
    var CONFIGURATION_TYPES = {
        rolesetting: "microsoft.entra.rolesetting",
        accesspackageassignmentpolicy: "microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy",
        conditionalaccesspolicy: "microsoft.entra.conditionalaccesspolicy",
        administrativeunit: "microsoft.entra.administrativeunit"
    };
    function findingLinks(rule, result) {
        var links = [];
        var add = function (label, href) { if (href && !links.some(function (link) { return link.href === href; })) links.push({ label: label, href: href }); };
        var enc = encodeURIComponent;
        var evidence = result.evidence || {};
        var id = result.rawObjectId || result.objectId || "";
        var type = String(result.objectType || "").toLowerCase();
        var configuration = CONFIGURATION_TYPES[type] && id ? "../ConfigurationAnalyzer/index.html#object=" + enc(CONFIGURATION_TYPES[type] + "|" + id) : "";
        switch (type) {
            case "rolesetting": {
                // The flow is "<role ID>|<path>"; results without FlowId carry it in the instance ID ("<role ID>.<path>").
                var flowId = evidence.FlowId || String(result.instanceId || "").replace(/^([^.]+)\.(.+)$/, "$1|$2");
                if (flowId) add("PIM Request Flow", "../PimRequestFlow/index.html#flow=" + enc(flowId));
                add("Configuration Analyzer", configuration);
                break;
            }
            case "accesspackageassignmentpolicy":
                add("Access Package Flow", "../AccessPackageFlow/index.html#flow=" + enc(evidence.FlowId || id));
                add("Configuration Analyzer", configuration);
                break;
            case "conditionalaccesspolicy":
                add("Conditional Access Analysis", "../ConditionalAccessAnalysis/index.html#flow=" + enc(id));
                add("Configuration Analyzer", configuration);
                break;
            case "administrativeunit":
                add("Configuration Analyzer", configuration);
                break;
            case "roledefinition":
                // Custom roles are not in the Classification Explorer catalog: the assignments of the role in the EAM Dashboard.
                (evidence.RoleAssignmentInstanceIds || []).slice(0, 3).forEach(function (assignmentId, index) {
                    add("EAM Dashboard assignment" + (index ? " " + (index + 1) : ""), "../EamDashboard/index.html#assignment=" + enc(assignmentId));
                });
                break;
            case "tenant":
                add("Privilege History", "../PrivilegeHistory/index.html");
                add("Tier Breach Analyzer", "../TierBreachAnalyzer/index.html");
                break;
            default:
                // The first path ID (the path of the first service) makes the link unambiguous: two assignments can share
                // object, role, service and scope. Tier Breach Analyzer matches it alone when it is given.
                if (rule.area === "TierBreach" && id && evidence.Role) add("Tier Breach Analyzer", "../TierBreachAnalyzer/index.html#sel=" + enc([id, evidence.Role, evidence.Service || (Array.isArray(evidence.Services) && evidence.Services[0]) || "", evidence.ScopeId || ""].concat(Array.isArray(evidence.PathIds) && evidence.PathIds[0] ? [evidence.PathIds[0]] : []).join("||")));
                if (evidence.RoleAssignmentInstanceId || evidence.AssignmentInstanceId) add("EAM Dashboard assignment", "../EamDashboard/index.html#assignment=" + enc(evidence.RoleAssignmentInstanceId || evidence.AssignmentInstanceId));
                // The EAM Dashboard and Access Path Map show the objects of the Privileged EAM export, like this inventory:
                // objects outside it (for example groups of access packages without privileged access) have no link.
                var inInventory = Boolean(id && objectsById[String(id).toLowerCase()]);
                if (inInventory) add("EAM Dashboard", "../EamDashboard/index.html#asset=" + enc(id));
                if (rule.area === "AccessPackageFlow") add("Access Package Flow", "../AccessPackageFlow/index.html");
                if (rule.area === "PrivilegeHistory") add("Privilege History", "../PrivilegeHistory/index.html");
                if (inInventory && OBJECT_TYPES.indexOf(type) >= 0) add("Access Path Map", "../AccessPathMap/index.html#node=" + enc(id.toUpperCase()));
        }
        return links;
    }
    // inObjectDrawer: leaves out the links to the object itself, which the object drawer has as buttons.
    function findingLinksHtml(rule, result, inObjectDrawer) {
        var links = findingLinks(rule, result).filter(function (link) {
            return !inObjectDrawer || (link.label !== "EAM Dashboard" && link.label !== "Access Path Map");
        });
        return links.length ? '<span class="pai-result-links">' + links.map(function (link) {
            return '<a class="cell-link" href="' + esc(link.href) + '">' + esc(link.label) + " &#8599;</a>";
        }).join("") + "</span>" : "";
    }
    var GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
    var CSA_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
    // v2 stores the local changes as a delta against a fingerprint of the repository file; v1 stored the full worklist.
    var STORE_KEY = "entraops.privilegedAssets.objectClassification.v2";
    var LEGACY_STORE_KEY = "entraops.privilegedAssets.objectClassification.v1";
    var VIEWS = { overview: "Overview", findings: "Findings", classification: "Object Classification" };
    var VIEW_TITLES = { overview: "Privileged Assets", findings: "Findings", classification: "Object Classification" };
    var PAGE_SIZE = 100;
    var MAX_IMPORT_BYTES = 5 * 1024 * 1024;
    var MAX_IMPORT_ROWS = 20000;
    var STATUS_ORDER = ["Failed", "Error", "Passed", "Skipped", "Excluded"];

    // The catalog severity; older data files carry only the report severity (fail/warn or high/medium/info).
    function severityName(value) {
        var text = String(value || "").toLowerCase();
        var name = SEVERITIES.filter(function (severity) { return severity.toLowerCase() === text; })[0];
        return name || { fail: "High", warn: "Medium" }[text] || "Info";
    }
    function severityClass(name) { return "sev-" + String(name || "Info").toLowerCase(); }

    // ---- Checks: one model for the rules of all sources, normalized once at load ------------------
    // Findings are evaluated in PowerShell: the Privileged Assets rules in the findings block of the data file
    // (camelCase), all rules in the saved results (findings.js of Save-EntraOpsFindingJson, PascalCase).
    // js/findings.js re-evaluates the Privileged Assets rules for What-if and for data files without findings.
    var FINDING_RULES = window.EntraOpsPrivilegedAssetsFindings;
    var DATA_FINDINGS = (DATA && DATA.findings) || null;
    var FINDINGS_BY_OBJECT = DATA_FINDINGS && DATA_FINDINGS.byObject ? DATA_FINDINGS.byObject : null;
    var SAVED_FINDINGS = window.ENTRAOPS_FINDINGS || null;
    var savedFindingsState = { status: SAVED_FINDINGS ? "loaded" : "missing", outside: 0, outsideRules: 0 };
    var RELATIONSHIP_FINDINGS = ["ownerLowerTier", "ownsHigherTier", "parentLowerTier"];

    // Fallback for results without the catalog title of a category: "JustInTimeAccess" -> "Just-in-time access".
    function categoryTitleOf(key) {
        if (key === "JustInTimeAccess") return "Just-in-time access";
        var text = String(key || "").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
        return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Other";
    }

    function normalizeRule(raw, area) {
        var get = function (name) {
            var value = raw[name];
            if (value == null || value === "") value = raw[name.charAt(0).toUpperCase() + name.slice(1)];
            return value == null ? "" : value;
        };
        var id = String(get("id") || get("ruleId"));
        var category = String(get("category"));
        // Without the catalog number, the category follows the first digit of the rule ID (EO.3001 -> 3).
        var number = Number(get("categoryNumber")) || Number((/^EO\.(\d)/i.exec(id) || [])[1]) || 99;
        var status = String(get("status") || "Failed");
        var toResult = function (result) {
            var instance = result.Instance || {};
            return {
                objectId: String(instance.ObjectId || "").toLowerCase(), rawObjectId: String(instance.ObjectId || ""), instanceId: String(instance.Id || ""),
                objectType: instance.ObjectType || "", displayName: instance.DisplayName || "", adminTierLevel: instance.AdminTierLevel,
                adminTierLevelName: String(instance.AdminTierLevelName || ""), message: result.Message || "",
                evidence: result.Evidence && typeof result.Evidence === "object" ? result.Evidence : {}
            };
        };
        // Failed instances of unclassified objects: not results, shown in the check panel on request.
        var unclassified = (raw.UnclassifiedResults || raw.unclassifiedResults || []).map(function (result) { return Object.assign(toResult(result), { unclassified: true }); });
        // Results accepted by a finding exception (risk accepted or dismissed): not counted, shown on request.
        var accepted = (raw.AcceptedResults || []).map(function (result) { return Object.assign(toResult(result), { exception: result.Exception || {} }); });
        // The resources of the rule (Microsoft Learn, Microsoft Graph, EntraOps docs), https links only.
        var references = (raw.References || raw.references || []).map(function (reference) {
            return { title: String(reference.Title || reference.title || reference.Url || reference.url || ""), url: String(reference.Url || reference.url || ""), type: String(reference.Type || reference.type || "") };
        }).filter(function (reference) { return /^https:\/\//i.test(reference.url); });
        return {
            id: id, key: String(get("key")), area: String(get("area") || area), category: category,
            categoryTitle: String(get("categoryTitle")) || categoryTitleOf(category), categoryNumber: number,
            title: String(get("title") || get("key") || id), checkTitle: String(get("checkTitle") || get("title") || id),
            description: String(get("description")), remediation: String(get("remediation")),
            effort: String(get("effort")), effortDescription: String(get("effortDescription")),
            userImpact: String(get("userImpact")), userImpactDescription: String(get("userImpactDescription")),
            severity: severityName(get("severity") || get("reportSeverity")), maesterTestId: String(get("maesterTestId")),
            status: STATUS_ORDER.indexOf(status) >= 0 ? status : "Skipped", reason: String(get("reason")),
            // Why a check was not evaluated (NotApplicable, MissingData, Unclassified) or that its Reason is a note of a result.
            reasonCode: String(get("reasonCode")),
            parameters: get("parameters") || {}, evaluatedCount: Number(get("evaluatedCount")) || 0, failedCount: Number(get("failedCount")) || 0,
            results: (raw.Results || raw.results || []).map(toResult),
            unclassifiedCount: Number(get("unclassifiedCount")) || unclassified.length, unclassifiedResults: unclassified,
            acceptedCount: Number(get("acceptedCount")) || accepted.length, acceptedResults: accepted,
            // Like the EntraOps Maester Pack: accepted results without their exception count as risk accepted.
            dismissedCount: accepted.filter(function (result) { return result.exception.State === "Dismissed"; }).length,
            exceptions: Array.isArray(raw.Exceptions) ? raw.Exceptions : [],
            references: references
        };
    }

    // ---- Evidence of a result: the rule-specific details of the evaluation, readable --------------------------
    // Labels of known evidence fields; other fields are split at their camel humps ("RoleDefinitionName" -> "Role definition name").
    var EVIDENCE_LABEL = {
        PimAssignmentType: "PIM assignment type", PIMAssignmentType: "PIM assignment type", ServiceTierLevel: "Service tier", RoleTierLevelName: "Role tier",
        ObjectTierLevelName: "Object tier", TierName: "Object tier", AssignmentTierName: "Highest role assignment tier", AccessTier: "Access tier", RoleTier: "Role tier",
        TargetTiers: "Tiers of the granted resources", Tier: "Tier", TransitiveBy: "Through group", RoleIsPrivileged: "Privileged role", ScopeId: "Scope ID", ScopeName: "Scope",
        RoleAssignmentScopeId: "Scope", RoleAssignmentType: "Assignment type", RoleAssignmentSubType: "Assignment sub type", RoleDefinitionName: "Role", RoleSystem: "RBAC system",
        OriginType: "Origin", OriginTenantId: "Origin tenant", OriginId: "ID in the origin tenant", ObjectTenantId: "Tenant of the object", RelatedObjectNames: "Related objects", OwnerIds: "Owners", GroupIds: "Groups",
        GroupNames: "Groups", ObjectIds: "Objects", PrivilegedMemberIds: "Privileged members", ExcludedControlPlane: "Excluded Control Plane identities",
        ExcludedControlPlaneRoles: "Excluded Control Plane roles", UnresolvedExcludedGroups: "Excluded groups not resolved", ScopedExclusions: "Scoped exclusions",
        GrantControls: "Grant controls", ActivationMaxDuration: "Maximum activation", MaxHours: "Configured maximum (hours)",
        TotalDrift: "Members without access package", Examples: "Examples", Previous: "Previous snapshot", Latest: "Newest snapshot", ReportDateTime: "Report time"
    };
    // Internal identifiers and hashes: collapsed under "Technical details".
    var EVIDENCE_TECHNICAL = /^(PathIds|SnapshotKey|FlowId|FlowIds|AssignmentInstanceId|RoleAssignmentInstanceIds?|.*CommitSha|.*InstanceIds?)$/;
    var TIER_NAME_VALUES = { ControlPlane: true, ManagementPlane: true, WorkloadPlane: true, UserAccess: true, Unclassified: true };

    function evidenceLabel(key) {
        if (EVIDENCE_LABEL[key]) return EVIDENCE_LABEL[key];
        var words = String(key).replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2").split(" ");
        return words.map(function (word, index) {
            if (/^(Id|Ids)$/.test(word)) return word.toUpperCase().replace("IDS", "IDs");
            if (/^(PIM|PAW|MFA|RBAC|UPN|API|AU)$/i.test(word)) return word.toUpperCase();
            return index ? word.toLowerCase() : word;
        }).join(" ");
    }

    // "PT8H" -> "8 hours", "P365D" -> "365 days", "PT1H30M" -> "1 hour 30 minutes"; null when it is no ISO 8601 duration.
    function durationText(value) {
        var match = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(String(value));
        if (!match || !/\d/.test(value)) return null;
        var units = ["year", "month", "week", "day", "hour", "minute", "second"];
        var parts = units.map(function (unit, index) { var number = Number(match[index + 1]); return number ? number + " " + unit + (number === 1 ? "" : "s") : ""; }).filter(Boolean);
        return parts.join(" ") || "0 seconds";
    }

    // Dates and times as yyyy-MM-dd (HH:mm in the local time zone); the invariant "MM/dd/yyyy HH:mm:ss" of PowerShell too.
    function dateText(value) {
        var text = String(value), date = null;
        var us = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(text);
        if (us) date = new Date(Date.UTC(Number(us[3]), Number(us[1]) - 1, Number(us[2]), Number(us[4] || 0), Number(us[5] || 0), Number(us[6] || 0)));
        else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(text)) date = new Date(text);
        if (!date || isNaN(date)) return null;
        var pad = function (number) { return number < 10 ? "0" + number : String(number); };
        return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) + " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
    }

    // One evidence value as escaped text: tier names and levels, durations, dates; object IDs with their name.
    function evidenceText(key, value) {
        if (value === true) return "Yes";
        if (value === false) return "No";
        if (typeof value === "string" && TIER_NAME_VALUES[value]) return TIER_LABEL[value];
        if (/TierLevel$/.test(key) && /^\d$/.test(String(value)) && LEVEL_TIER[Number(value)]) return TIER_LABEL[LEVEL_TIER[Number(value)]] + " (Tier " + value + ")";
        var duration = typeof value === "string" ? durationText(value) : null;
        if (duration) return duration;
        var date = typeof value === "string" ? dateText(value) : null;
        if (date) return date;
        if (typeof value === "string" && GUID.test(value)) {
            var info = relatedInfo(value);
            if (info.source !== "Unresolved" && info.displayName !== info.id) return info.displayName + " (" + value + ")";
        }
        return value && typeof value === "object" ? JSON.stringify(value) : String(value);
    }

    // A list of objects (for example the examples of the access drift) as a small table with the columns that have values.
    function evidenceTable(rows) {
        var columns = [];
        rows.forEach(function (row) { Object.keys(row).forEach(function (key) { if (row[key] !== "" && row[key] != null && columns.indexOf(key) < 0) columns.push(key); }); });
        if (!columns.length) return "";
        return '<table class="pai-evidence-table"><thead><tr>' + columns.map(function (key) { return "<th>" + esc(evidenceLabel(key)) + "</th>"; }).join("") + "</tr></thead><tbody>" +
            rows.map(function (row) { return "<tr>" + columns.map(function (key) { return "<td>" + (row[key] === "" || row[key] == null ? '<span class="muted">-</span>' : esc(evidenceText(key, row[key]))) + "</td>"; }).join("") + "</tr>"; }).join("") + "</tbody></table>";
    }

    function evidenceValueHtml(key, value) {
        if (Array.isArray(value)) {
            if (value.length && value.every(function (item) { return item && typeof item === "object" && !Array.isArray(item); })) return evidenceTable(value);
            if (value.length === 1) return esc(evidenceText(key, value[0]));
            // A list (for example Services or the groups of a nesting) shows one value per line.
            return value.map(function (item) { return '<span class="pai-evidence-item">' + esc(evidenceText(key, item)) + "</span>"; }).join("");
        }
        if (value && typeof value === "object") return evidenceTable([value]);
        return esc(evidenceText(key, value));
    }

    // Fields that repeat other fields are left out: the first service of Services, the IDs of named related objects,
    // a count equal to the total, and "no more examples".
    function evidenceHidden(evidence, key) {
        var value = evidence[key];
        if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) return true;
        if (key === "Service" && Array.isArray(evidence.Services) && evidence.Services.indexOf(value) >= 0) return true;
        if (key === "RelatedObjectIds" && Array.isArray(evidence.RelatedObjectNames) && evidence.RelatedObjectNames.length) return true;
        if (key === "GroupIds" && Array.isArray(evidence.GroupNames) && evidence.GroupNames.length) return true;
        if (key === "Count" && evidence.TotalDrift != null && Number(evidence.TotalDrift) === Number(value)) return true;
        if (key === "MoreExamples" && value === false) return true;
        return false;
    }

    // The evidence as a collapsed list under the message; internal IDs and hashes in a collapsed sub-section.
    function evidenceHtml(evidence) {
        evidence = evidence || {};
        var keys = Object.keys(evidence).filter(function (key) { return !evidenceHidden(evidence, key); });
        if (!keys.length) return "";
        // A table (a list of objects) takes the full width under its label.
        var row = function (key) {
            var value = evidence[key];
            var wide = value && typeof value === "object" && (!Array.isArray(value) || (value.length && value.every(function (item) { return item && typeof item === "object" && !Array.isArray(item); })));
            var cls = wide ? ' class="pai-evidence-wide"' : "";
            return "<dt" + cls + ">" + esc(evidenceLabel(key)) + "</dt><dd" + cls + ">" + evidenceValueHtml(key, value) + "</dd>";
        };
        var main = keys.filter(function (key) { return !EVIDENCE_TECHNICAL.test(key); });
        var technical = keys.filter(function (key) { return EVIDENCE_TECHNICAL.test(key); });
        if (!main.length) return '<details class="pai-evidence pai-evidence-technical"><summary>Technical details (' + technical.length + ')</summary><dl class="pai-evidence-list">' + technical.map(row).join("") + "</dl></details>";
        return '<details class="pai-evidence"><summary>Evidence (' + main.length + ")</summary>" +
            (main.length ? '<dl class="pai-evidence-list">' + main.map(row).join("") + "</dl>" : "") +
            (technical.length ? '<details class="pai-evidence pai-evidence-technical"><summary>Technical details (' + technical.length + ')</summary><dl class="pai-evidence-list">' + technical.map(row).join("") + "</dl></details>" : "") +
            "</details>";
    }

    // The resources of a rule as a list of links (opened in a new tab).
    function referencesHtml(rule) {
        if (!rule.references || !rule.references.length) return "";
        return '<ul class="drawer-list pai-references">' + rule.references.map(function (reference) {
            return '<li><a class="cell-link" href="' + esc(reference.url) + '" target="_blank" rel="noopener noreferrer">' + esc(reference.title) + " &#8599;</a>" +
                (reference.type ? ' <span class="muted pai-small">' + esc({ Learn: "Microsoft Learn", Graph: "Microsoft Graph", EntraOps: "EntraOps docs", Maester: "Maester" }[reference.type] || reference.type) + "</span>" : "") + "</li>";
        }).join("") + "</ul>";
    }

    // The Privileged Assets rules behind the object findings: the rules of the data file, else the catalog entries
    // of js/findings.js. Excluded (or deprecated) rules report no findings.
    var CATALOG_FALLBACK = {};
    (FINDING_RULES.RULES || []).forEach(function (rule) { CATALOG_FALLBACK[rule.key] = rule; });
    var DATA_RULES = (DATA_FINDINGS && Array.isArray(DATA_FINDINGS.rules) ? DATA_FINDINGS.rules : []).map(function (raw) {
        var fallback = CATALOG_FALLBACK[raw.key] || {};
        return normalizeRule(raw.category ? raw : Object.assign({}, raw, { category: fallback.category || "" }), "PrivilegedAssets");
    });
    var PA_RULES = (DATA_RULES.length ? DATA_RULES : (FINDING_RULES.RULES || []).map(function (raw) { return normalizeRule(raw, "PrivilegedAssets"); }))
        .filter(function (rule) { return rule.status !== "Excluded"; });
    var PA_RULE_BY_KEY = {};
    var PA_RULE_ORDER = {};
    PA_RULES.forEach(function (rule, index) { PA_RULE_BY_KEY[rule.key] = rule; PA_RULE_ORDER[rule.key] = index; });
    // The saved Privileged Assets results per object and rule key (attachSavedFindings), null without saved results.
    var SAVED_PA_BY_OBJECT = null;
    var SAVED_PA_RULE_BY_KEY = {};
    var SAVED_RULES = SAVED_FINDINGS && Array.isArray(SAVED_FINDINGS.Rules) ? SAVED_FINDINGS.Rules.filter(function (rule) { return rule && (rule.RuleId || rule.Id); }).map(function (raw) { return normalizeRule(raw, ""); }) : [];

    // Failed Maester tests (Maester test results joined with their affected objects) per privileged object.
    var MAESTER = (DATA || {}).maester || null;
    var MAESTER_TESTS = (MAESTER && MAESTER.tests) || {};
    var MAESTER_OTHER_OBJECTS = 12;

    function maesterTest(id) { return Object.prototype.hasOwnProperty.call(MAESTER_TESTS, id) ? MAESTER_TESTS[id] : null; }
    // Maester tests use the severity scale of the checks; tests without a known severity sort last.
    function maesterSeverityLabel(test) {
        var text = String((test && test.severity) || "").toLowerCase();
        return SEVERITIES.filter(function (severity) { return severity.toLowerCase() === text; })[0] || "Unknown";
    }
    function maesterSeverityClass(test) { return severityClass(severityName(test && test.severity)); }
    function maesterRank(test) { var label = maesterSeverityLabel(test); return label === "Unknown" ? 5 : SEVERITY_RANK[label]; }

    function computeMaester(object) {
        var byTest = Object.create(null);
        (object.maesterAssets || []).forEach(function (asset) {
            (asset.tests || []).forEach(function (id) {
                var test = maesterTest(id);
                if (!test) return;
                (byTest[id] = byTest[id] || { testId: id, test: test, assets: [] }).assets.push(asset);
            });
        });
        return Object.keys(byTest).map(function (id) { return byTest[id]; }).sort(function (a, b) {
            return maesterRank(a.test) - maesterRank(b.test) || a.testId.localeCompare(b.testId);
        });
    }

    var state = {
        search: "", whatIf: false, sort: "tier", sortDir: 1, page: 0, selected: new Set(), worklistEntries: {}, script: "", fileChanged: false
    };
    // Filter select values are kept apart from the render state: they're written by key from the DOM and only compared, never rendered.
    var filters = { type: "", subType: "", tier: "", assignmentTier: "", au: "", restricted: "", sync: "", finding: "", worklist: "" };
    // Filters of the "More filters" panel (the badge on its button counts the active ones).
    var MORE_FILTERS = ["assignmentTier", "au", "restricted", "sync", "worklist"];
    var objects = [];
    // Without prototype: an ID of a deep link like "constructor" is not an object.
    var objectsById = Object.create(null);
    var related = {};
    var fileEntries = {};

    function $(id) { return document.getElementById(id); }

    function esc(value) {
        return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
        });
    }

    // Escaped text with line-break opportunities at separators (and optionally camelCase humps), so long identifiers don't widen table columns.
    function breakable(value, camelCase) {
        var html = esc(value).replace(/([.\-_\/])/g, "$1<wbr>");
        return camelCase ? html.replace(/([a-z])(?=[A-Z])/g, "$1<wbr>") : html;
    }

    function tierBadge(tier) {
        var name = Object.prototype.hasOwnProperty.call(TIER_LABEL, tier) ? tier : "Unclassified";
        return '<span class="tier-badge tier-' + name.toLowerCase() + '"><span class="tier-dot"></span>' + esc(TIER_LABEL[name]) + "</span>";
    }

    function normalizeTier(value) {
        var text = String(value == null ? "" : value).trim();
        for (var i = 0; i < TIERS.length; i++) {
            if (TIERS[i].toLowerCase() === text.toLowerCase()) return TIERS[i];
        }
        return null;
    }

    function relatedInfo(id) {
        var key = String(id || "").toLowerCase();
        if (objectsById[key]) {
            var object = objectsById[key];
            return { id: object.objectId, displayName: object.displayName, objectType: object.objectType, objectSubType: object.objectSubType, tierName: effectiveTier(object), inInventory: true, source: "PrivilegedEAM" };
        }
        var entry = related[key];
        if (entry) {
            var inventoryId = entry.objectId && objectsById[entry.objectId] ? entry.objectId : null;
            return {
                id: inventoryId || key, displayName: entry.displayName || key, objectType: entry.objectType, objectSubType: entry.objectSubType,
                tierName: inventoryId ? effectiveTier(objectsById[inventoryId]) : "", inInventory: Boolean(inventoryId), source: entry.source,
                operatingSystem: entry.operatingSystem, isCompliant: entry.isCompliant, isManaged: entry.isManaged, userPrincipalName: entry.userPrincipalName
            };
        }
        return { id: key, displayName: key, objectType: "", tierName: "", inInventory: false, source: "Unresolved" };
    }

    // ---- Worklist (Object Classification File) --------------------------------------------------
    function entryKey(entry) {
        return [entry.adminTierLevelName, entry.objectType || "", entry.justification || ""].join("|");
    }

    function sameEntry(left, right) {
        return ["objectId", "objectType", "objectDisplayName", "adminTierLevelName", "justification"].every(function (field) {
            return String(left[field] || "") === String(right[field] || "");
        });
    }

    // Stable FNV-1a hash of the repository file entries, used to detect that the file changed since the local edits.
    function fileFingerprint() {
        var text = JSON.stringify(Object.keys(fileEntries).sort().map(function (id) {
            var entry = fileEntries[id];
            return [id, entry.objectType, entry.objectDisplayName, entry.adminTierLevelName, entry.justification];
        }));
        var hash = 0x811c9dc5;
        for (var i = 0; i < text.length; i++) {
            hash ^= text.charCodeAt(i);
            hash = Math.imul(hash, 0x01000193) >>> 0;
        }
        return Object.keys(fileEntries).length + "-" + hash.toString(16);
    }

    function readStore(key) {
        try {
            var stored = JSON.parse(localStorage.getItem(key) || "null");
            return stored && typeof stored === "object" && stored.tenant === (DATA.tenantName || "") ? stored : null;
        } catch (_) { return null; }
    }

    // The worklist is the current repository file with the local delta (upserts and removals) applied on top, so file
    // entries added or removed in the repository after the local edits are never dropped or resurrected.
    function loadWorklist() {
        var entries = JSON.parse(JSON.stringify(fileEntries));
        var upsert = function (raw) {
            var entry = sanitizeEntry(raw);
            if (entry.ok) entries[entry.value.objectId] = entry.value;
        };
        state.fileChanged = false;
        var stored = readStore(STORE_KEY);
        if (stored && stored.version === 2) {
            (Array.isArray(stored.removals) ? stored.removals : []).forEach(function (id) { delete entries[String(id).toLowerCase()]; });
            if (stored.upserts && typeof stored.upserts === "object") Object.keys(stored.upserts).forEach(function (id) { upsert(stored.upserts[id]); });
            state.fileChanged = stored.baseFingerprint !== fileFingerprint();
            return entries;
        }
        // A v1 full-list worklist has no known file snapshot: keep its adds and edits, but never drop current file entries.
        var legacy = readStore(LEGACY_STORE_KEY);
        if (legacy && legacy.entries && typeof legacy.entries === "object") {
            Object.keys(legacy.entries).forEach(function (id) { upsert(legacy.entries[id]); });
            state.fileChanged = true;
        }
        return entries;
    }

    function saveWorklist() {
        var upserts = {}, removals = [];
        Object.keys(state.worklistEntries).sort().forEach(function (id) {
            if (!fileEntries[id] || !sameEntry(state.worklistEntries[id], fileEntries[id])) upserts[id] = state.worklistEntries[id];
        });
        Object.keys(fileEntries).sort().forEach(function (id) { if (!state.worklistEntries[id]) removals.push(id); });
        try {
            localStorage.setItem(STORE_KEY, JSON.stringify({
                version: 2, tenant: DATA.tenantName || "", baseFingerprint: fileFingerprint(), upserts: upserts, removals: removals
            }));
            localStorage.removeItem(LEGACY_STORE_KEY);
        } catch (_) { /* Local storage can be unavailable in hardened browsers. */ }
    }

    function resetWorklistToFile() {
        state.worklistEntries = JSON.parse(JSON.stringify(fileEntries));
        state.fileChanged = false;
        try {
            localStorage.removeItem(STORE_KEY);
            localStorage.removeItem(LEGACY_STORE_KEY);
        } catch (_) { /* ignore */ }
    }

    function confirmResetWorklist() {
        if (!window.confirm("Discard all worklist changes in this browser and reload the entries from the repository file?")) return false;
        resetWorklistToFile();
        renderAll();
        return true;
    }

    function sanitizeEntry(raw) {
        if (!raw || typeof raw !== "object") return { ok: false, reason: "Empty row" };
        var get = function (name) {
            var match = Object.keys(raw).filter(function (key) { return key.toLowerCase() === name.toLowerCase(); })[0];
            return match === undefined || raw[match] == null ? "" : String(raw[match]).trim();
        };
        var stripGuard = function (text) { return /^'[=+\-@\t\r]/.test(text) ? text.slice(1) : text; };
        var objectId = get("ObjectId").toLowerCase();
        if (!GUID.test(objectId)) return { ok: false, reason: "ObjectId '" + get("ObjectId").slice(0, 60) + "' is not a GUID" };
        var tier = normalizeTier(get("AdminTierLevelName"));
        if (!tier) return { ok: false, reason: objectId + ": AdminTierLevelName '" + get("AdminTierLevelName").slice(0, 40) + "' is not one of " + TIERS.join(", ") };
        var objectType = get("ObjectType").toLowerCase();
        if (objectType && OBJECT_TYPES.indexOf(objectType) < 0) return { ok: false, reason: objectId + ": ObjectType '" + objectType.slice(0, 40) + "' is not one of " + OBJECT_TYPES.join(", ") };
        var object = objectsById[objectId];
        if (object && objectType && object.objectType !== objectType) return { ok: false, reason: objectId + ": ObjectType '" + objectType + "' does not match the inventory object type '" + object.objectType + "'" };
        return {
            ok: true,
            value: {
                objectId: objectId,
                objectType: objectType || (object ? object.objectType : ""),
                objectDisplayName: stripGuard(get("ObjectDisplayName")).slice(0, 256) || (object ? object.displayName : ""),
                adminTierLevelName: tier,
                justification: stripGuard(get("Justification")).slice(0, 500)
            }
        };
    }

    function setTargetTier(ids, tier, justification) {
        ids.forEach(function (id) {
            var object = objectsById[id];
            if (!object) return;
            state.worklistEntries[id] = {
                objectId: id, objectType: object.objectType, objectDisplayName: object.displayName,
                adminTierLevelName: tier, justification: String(justification || "").trim().slice(0, 500)
            };
        });
        saveWorklist();
    }

    function removeFromWorklist(ids) {
        ids.forEach(function (id) { delete state.worklistEntries[id]; });
        saveWorklist();
    }

    function worklistStatus(id) {
        var local = state.worklistEntries[id], file = fileEntries[id];
        if (local && !file) return "Added";
        if (!local && file) return "Removed";
        if (local && file && entryKey(local) !== entryKey(file)) return "Changed";
        return local ? "Unchanged" : "";
    }

    function pendingChanges() {
        var ids = new Set(Object.keys(state.worklistEntries).concat(Object.keys(fileEntries)));
        var changes = { Added: 0, Changed: 0, Removed: 0 };
        ids.forEach(function (id) {
            var status = worklistStatus(id);
            if (changes[status] !== undefined) changes[status]++;
        });
        return changes;
    }

    // ---- Tier evaluation and findings ------------------------------------------------------------
    // The What-if view evaluates objects with the tier of their worklist entry.
    function whatIfTier(objectId) {
        var entry = state.whatIf ? state.worklistEntries[objectId] : null;
        return entry ? entry.adminTierLevelName : null;
    }

    function findingEnv() {
        return { objectsById: objectsById, related: related, tierOverride: whatIfTier };
    }

    function effectiveTier(object) { return FINDING_RULES.effectiveTier(object, findingEnv()); }

    function requiredLevel(object) { return FINDING_RULES.requiredLevel(object, findingEnv()); }

    function relatedLevel(id) { return FINDING_RULES.relatedLevel(id, findingEnv()); }

    // The Privileged Assets findings of an object: evaluated in this browser for What-if (and for data without
    // findings), else the saved results of all checks (accepted findings left out, with their messages), else the
    // findings block of the data file.
    function computeFindings(object) {
        var saved = !state.whatIf && SAVED_PA_BY_OBJECT;
        var inBrowser = !saved && (state.whatIf || !FINDINGS_BY_OBJECT);
        var found = saved ? Object.keys(SAVED_PA_BY_OBJECT[object.objectId] || {}) : inBrowser ? FINDING_RULES.compute(object, findingEnv()) : (FINDINGS_BY_OBJECT[object.objectId] || []);
        return found.filter(function (key) { return paRule(key) && !(inBrowser && acceptedInFile(paRule(key).id, object.objectId)); }).sort(function (a, b) { return paOrder(a) - paOrder(b); });
    }

    function paRule(key) { return PA_RULE_BY_KEY[key] || SAVED_PA_RULE_BY_KEY[key] || null; }

    function paOrder(key) { return Object.prototype.hasOwnProperty.call(PA_RULE_ORDER, key) ? PA_RULE_ORDER[key] : 500; }

    // All findings of an object, most severe first: the Privileged Assets findings and the saved findings of the
    // other rules (one item per rule with its results).
    function findingItems(object) {
        var item = function (filter, rule, results, order) { return { filter: filter, rule: rule, label: rule.title, severity: rule.severity, ruleId: rule.id, results: results, order: order }; };
        var savedResults = !state.whatIf && SAVED_PA_BY_OBJECT ? SAVED_PA_BY_OBJECT[object.objectId] || {} : {};
        var items = object._findings.map(function (key) { return item(key, paRule(key), savedResults[key] || [], paOrder(key)); });
        (object._extra || []).forEach(function (entry) { items.push(item("rule:" + entry.rule.id, entry.rule, entry.results, 1000)); });
        return items.sort(function (a, b) { return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.order - b.order || a.ruleId.localeCompare(b.ruleId); });
    }

    // Rank of the most severe finding of an object (EntraOps and Maester), 5 without findings.
    function topSeverityRank(object) {
        var rank = object._items.length ? SEVERITY_RANK[object._items[0].severity] : 5;
        (object._maester || []).forEach(function (finding) { rank = Math.min(rank, maesterRank(finding.test)); });
        return rank;
    }

    // Matches the saved results of the other rules to the inventory objects (once per page load). The saved
    // Privileged Assets results replace the findings block of the data file outside What-if (SAVED_PA_BY_OBJECT).
    function attachSavedFindings() {
        if (!SAVED_FINDINGS) return;
        if (SAVED_FINDINGS.TenantId && DATA.homeTenantId && String(SAVED_FINDINGS.TenantId).toLowerCase() !== String(DATA.homeTenantId).toLowerCase()) {
            savedFindingsState.status = "otherTenant";
            return;
        }
        var outsideRules = {};
        var savedPa = SAVED_RULES.filter(function (rule) { return rule.area === "PrivilegedAssets" && rule.key; });
        if (savedPa.length) {
            SAVED_PA_BY_OBJECT = {};
            savedPa.forEach(function (rule) {
                SAVED_PA_RULE_BY_KEY[rule.key] = rule;
                if (rule.status !== "Failed") return;
                rule.results.forEach(function (result) {
                    if (!objectsById[result.objectId]) return;
                    var byRule = SAVED_PA_BY_OBJECT[result.objectId] = SAVED_PA_BY_OBJECT[result.objectId] || {};
                    (byRule[rule.key] = byRule[rule.key] || []).push(result);
                });
            });
        }
        SAVED_RULES.forEach(function (rule) {
            if (rule.area === "PrivilegedAssets" || rule.status !== "Failed") return;
            var byObject = {};
            rule.results.forEach(function (result) {
                if (!objectsById[result.objectId]) { savedFindingsState.outside++; outsideRules[rule.id] = true; return; }
                (byObject[result.objectId] = byObject[result.objectId] || []).push(result);
            });
            Object.keys(byObject).forEach(function (id) { (objectsById[id]._extra = objectsById[id]._extra || []).push({ rule: rule, results: byObject[id] }); });
        });
        savedFindingsState.outsideRules = Object.keys(outsideRules).length;
    }

    // ---- Filters, sorting, rendering ---------------------------------------------------------------
    function fillSelect(id, options, allLabel) {
        var select = $(id);
        select.innerHTML = '<option value="">' + esc(allLabel || "All") + "</option>" + options.map(function (option) {
            return '<option value="' + esc(option.value) + '">' + esc(option.label) + "</option>";
        }).join("");
    }

    // Entries grouped by the category of their rule, in catalog order: [{ key, title, entries }].
    function categoryGroups(entries, ruleOf) {
        var groups = {};
        entries.forEach(function (entry) {
            var rule = ruleOf(entry);
            (groups[rule.category] = groups[rule.category] || { key: rule.category, title: rule.categoryTitle, number: rule.categoryNumber, entries: [] }).entries.push(entry);
        });
        return Object.keys(groups).map(function (key) { return groups[key]; }).sort(function (a, b) { return a.number - b.number || a.title.localeCompare(b.title); });
    }

    // The finding filter: overall options, the rules with findings grouped by category, and the Maester tests.
    function fillFindingFilter() {
        var option = function (value, label) { return '<option value="' + esc(value) + '">' + esc(label) + "</option>"; };
        var counts = {};
        objects.forEach(function (object) { object._items.forEach(function (item) { counts[item.filter] = (counts[item.filter] || 0) + 1; }); });
        var entries = PA_RULES.map(function (rule) { return { value: rule.key, rule: rule, count: counts[rule.key] || 0 }; });
        SAVED_RULES.forEach(function (rule) {
            if (rule.area !== "PrivilegedAssets" && counts["rule:" + rule.id]) entries.push({ value: "rule:" + rule.id, rule: rule, count: counts["rule:" + rule.id] });
        });
        var html = option("", "All objects") + '<optgroup label="Overall">' + option("__any", "Any finding") + option("__relationship", "Any relationship finding") +
            SEVERITIES.slice(0, 3).map(function (severity, index) { return option("sev:" + severity, index ? severity + " or higher" : severity); }).join("") + "</optgroup>";
        categoryGroups(entries, function (entry) { return entry.rule; }).forEach(function (group) {
            var sorted = group.entries.sort(function (a, b) { return a.rule.id.localeCompare(b.rule.id) || a.rule.title.localeCompare(b.rule.title); });
            html += '<optgroup label="' + esc(group.title) + '">' + sorted.map(function (entry) { return option(entry.value, entry.rule.title + " (" + entry.count + ")"); }).join("") + "</optgroup>";
        });
        var maester = maesterFilterOptions();
        if (maester.length) html += '<optgroup label="Maester">' + maester.map(function (entry) { return option(entry.value, entry.label); }).join("") + "</optgroup>";
        $("paiFilterFinding").innerHTML = html;
        $("paiFilterFinding").value = filters.finding;
        if ($("paiFilterFinding").value !== filters.finding) filters.finding = "";
    }

    function initFilters() {
        var units = {};
        objects.forEach(function (object) {
            (object.administrativeUnits || []).forEach(function (unit) { units[unit.id] = unit.displayName || unit.id; });
        });
        var tierOptions = TIERS.concat(["Unclassified"]).map(function (tier) { return { value: tier, label: TIER_LABEL[tier] }; });
        fillSelect("paiFilterAssignmentTier", tierOptions);
        fillSelect("paiFilterAu", [{ value: "__none", label: "No administrative unit" }].concat(Object.keys(units).sort(function (a, b) { return units[a].localeCompare(units[b]); }).map(function (id) { return { value: id, label: units[id] }; })));
        fillSelect("paiFilterRestricted", ["Applied", "Not applied", "Conflict", "Not available"].map(function (value) { return { value: value, label: value }; }));
        fillSelect("paiFilterSync", [{ value: "cloud", label: "Cloud-only" }, { value: "hybrid", label: "Synchronized (hybrid)" }]);
        fillSelect("paiFilterWorklist", [{ value: "in", label: "In worklist" }, { value: "pending", label: "Pending changes" }, { value: "out", label: "Not in worklist" }]);
        $("paiBulkTier").innerHTML = TIERS.map(function (tier) { return '<option value="' + tier + '">' + esc(TIER_LABEL[tier]) + "</option>"; }).join("");
    }

    // skip leaves out one filter, for the counts of its pills.
    function matches(object, skip) {
        if (state.search) {
            var haystack = [object.displayName, object.userPrincipalName, object.objectId, object._findingText].join(" ").toLowerCase();
            if (haystack.indexOf(state.search) < 0) return false;
        }
        if (skip !== "type" && filters.type && object.objectType !== filters.type) return false;
        if (skip !== "subType" && skip !== "type" && filters.subType && object.objectSubType !== filters.subType) return false;
        if (skip !== "tier" && filters.tier && effectiveTier(object) !== filters.tier) return false;
        if (filters.assignmentTier && object.assignmentSummary.highestTierName !== filters.assignmentTier) return false;
        if (filters.au === "__none" && (object.administrativeUnits || []).length) return false;
        if (filters.au && filters.au !== "__none" && !(object.administrativeUnits || []).some(function (unit) { return unit.id === filters.au; })) return false;
        if (filters.restricted && object.restrictedManagement !== filters.restricted) return false;
        if (filters.sync === "hybrid" && !object.onPremSynchronized) return false;
        if (filters.sync === "cloud" && object.onPremSynchronized) return false;
        if (filters.finding === "__any" && !object._items.length && !object._maester.length) return false;
        if (filters.finding.indexOf("sev:") === 0 && topSeverityRank(object) > SEVERITY_RANK[filters.finding.slice(4)]) return false;
        if (filters.finding.indexOf("rule:") === 0 && !object._items.some(function (item) { return item.filter === filters.finding; })) return false;
        if (filters.finding === "__relationship" && !object._findings.some(function (id) { return RELATIONSHIP_FINDINGS.indexOf(id) >= 0; })) return false;
        if (filters.finding === "__maester" && !object._maester.length) return false;
        if (filters.finding.indexOf("maester:") === 0 && !object._maester.some(function (finding) { return finding.testId === filters.finding.slice(8); })) return false;
        if (filters.finding && !/^(__|maester:|sev:|rule:)/.test(filters.finding) && object._findings.indexOf(filters.finding) < 0) return false;
        if (filters.worklist === "in" && !state.worklistEntries[object.objectId]) return false;
        if (filters.worklist === "out" && state.worklistEntries[object.objectId]) return false;
        if (filters.worklist === "pending" && ["Added", "Changed", "Removed"].indexOf(worklistStatus(object.objectId)) < 0) return false;
        return true;
    }

    function relationshipCount(object) {
        return ["owners", "sponsors", "ownedObjects", "ownedDevices"].reduce(function (sum, key) { return sum + (object[key] || []).length; }, 0) + (object.identityParent ? 1 : 0);
    }

    function sortValue(object) {
        switch (state.sort) {
            case "name": return object.displayName.toLowerCase();
            case "type": return (object.objectType + "|" + object.objectSubType).toLowerCase();
            case "assignmentTier": return TIER_ORDER[object.assignmentSummary.highestTierName];
            case "relationships": return -relationshipCount(object);
            case "findings": return topSeverityRank(object) * 10000 - (object._items.length + object._maester.length);
            default: return TIER_ORDER[effectiveTier(object)];
        }
    }

    function filteredObjects() {
        return objects.filter(matches).sort(function (a, b) {
            var left = sortValue(a), right = sortValue(b);
            if (left < right) return -state.sortDir;
            if (left > right) return state.sortDir;
            return a.displayName.localeCompare(b.displayName);
        });
    }

    function refreshFindings() {
        objects.forEach(function (object) {
            object._findings = computeFindings(object);
            object._maester = computeMaester(object);
            object._items = findingItems(object);
            object._findingText = object._items.map(function (item) { return item.ruleId + " " + item.label; }).join(" ");
        });
    }

    // Stat tiles in a grid with one row on wide screens (pai-stat-n<count> sets the columns).
    function statTilesHtml(container, tiles, attribute) {
        container.className = "grid pai-stat-grid pai-stat-n" + tiles.length;
        container.innerHTML = tiles.map(function (tile, index) {
            return '<button class="stat stat-action ' + (tile.cls || "") + '" type="button" ' + attribute + '="' + esc(tile.key != null ? tile.key : index) + '"' + (tile.title ? ' title="' + esc(tile.title) + '"' : "") + '><div class="stat-accent"></div><div class="stat-label">' + esc(tile.label) +
                '</div><div class="stat-value">' + esc(tile.value) + '</div><div class="stat-sub">' + esc(tile.sub) + "</div></button>";
        }).join("");
    }

    // The tier breach and relationship findings are selected with the Finding filter; the tiles show the totals.
    function renderStats() {
        var pending = pendingChanges();
        // Objects by their most severe finding (EntraOps and Maester); Maester tests without a known severity count as
        // "unknown severity", like the "Any finding" filter counts them.
        var bySeverity = {};
        var withFindings = objects.filter(function (object) {
            if (!object._items.length && !object._maester.length) return false;
            var label = SEVERITIES[topSeverityRank(object)] || "Unknown";
            bySeverity[label] = (bySeverity[label] || 0) + 1;
            return true;
        }).length;
        var tierCounts = {};
        objects.forEach(function (object) { var tier = effectiveTier(object); tierCounts[tier] = (tierCounts[tier] || 0) + 1; });
        var tiles = [
            {
                label: "Privileged objects", value: objects.length, filter: {}, title: "Privileged objects of the Privileged EAM export by object tier",
                sub: TIERS.concat(["Unclassified"]).filter(function (tier) { return tier !== "WorkloadPlane" || tierCounts[tier]; }).map(function (tier) { return TIER_LABEL[tier] + ": " + (tierCounts[tier] || 0); }).join(" · ")
            },
            {
                label: "Objects with findings", value: withFindings, filter: { finding: "__any" }, cls: "pai-stat-findings",
                title: "Objects with at least one open finding (EntraOps checks and Maester tests), counted once by their most severe finding",
                sub: withFindings ? SEVERITIES.concat(["Unknown"]).filter(function (severity) { return bySeverity[severity]; }).map(function (severity) {
                    return bySeverity[severity] + " " + (severity === "Unknown" ? "unknown severity" : severity.toLowerCase());
                }).join(" · ") + " · by most severe finding" : "No findings"
            }
        ];
        if (MAESTER) {
            var maesterTests = {};
            objects.forEach(function (object) { object._maester.forEach(function (finding) { maesterTests[finding.testId] = true; }); });
            var executed = MAESTER.executedAt ? new Date(MAESTER.executedAt) : null;
            tiles.push({
                label: "Objects with Maester findings", value: objects.filter(function (object) { return object._maester.length; }).length,
                sub: Object.keys(maesterTests).length + " failed Maester tests" + (executed && !isNaN(executed) ? " · run " + executed.toLocaleDateString() : ""), filter: { finding: "__maester" }
            });
        }
        tiles.push({ label: "Object Classification worklist", value: Object.keys(state.worklistEntries).length, sub: pending.Added + " added · " + pending.Changed + " changed · " + pending.Removed + " removed", view: "classification" });
        statTilesHtml($("paiStats"), tiles, "data-stat");
        $("paiStats").querySelectorAll("[data-stat]").forEach(function (button) {
            button.addEventListener("click", function () {
                var tile = tiles[Number(button.getAttribute("data-stat"))];
                if (tile.view) { setView(tile.view, true); return; }
                resetFilters(false);
                Object.keys(tile.filter).forEach(function (key) { filters[key] = tile.filter[key]; });
                if (MORE_FILTERS.some(function (key) { return filters[key]; })) setMoreFilters(true);
                syncFilterControls();
                renderInventory();
                $("secPaiInventory").scrollIntoView({ behavior: "smooth", block: "start" });
            });
        });
    }

    function assignmentCell(object) {
        var summary = object.assignmentSummary;
        var parts = TIERS.concat(["Unclassified"]).filter(function (tier) { return summary.byTier[tier]; }).map(function (tier) {
            return '<span class="pai-tier-count tier-' + tier.toLowerCase() + '" title="' + esc(TIER_LABEL[tier]) + '">' + esc(TIER_LABEL[tier].split(" ")[0]) + " " + summary.byTier[tier] + "</span>";
        });
        return '<div class="pai-assign">' + (parts.join(" ") || '<span class="muted">No assignments</span>') + '</div><div class="muted pai-small"><span class="pai-nowrap">' + summary.total + ' total ·</span> <span class="pai-nowrap">' + summary.eligible + ' eligible ·</span> <span class="pai-nowrap">' + summary.active + " active</span></div>";
    }

    function relationshipCell(object) {
        var items = [];
        [["owners", "Owners"], ["sponsors", "Sponsors"], ["ownedObjects", "Owned objects"], ["ownedDevices", "Owned devices"]].forEach(function (pair) {
            var count = (object[pair[0]] || []).length;
            if (count) items.push('<span class="chip">' + esc(pair[1]) + " " + count + "</span>");
        });
        if (object.identityParent) items.push('<span class="chip">Identity parent</span>');
        return items.join(" ") || '<span class="muted">None</span>';
    }

    // The highest severity, the number of findings (EntraOps and Maester) and the most severe one on one line;
    // all of them are in the side panel. compact leaves out the finding (phone layout, under the object name).
    function findingsSummary(object, compact) {
        var items = object._items, maester = object._maester || [];
        var count = items.length + maester.length;
        if (!count) return compact ? "" : '<span class="muted">None</span>';
        var maesterFirst = maester.length && (!items.length || maesterRank(maester[0].test) < SEVERITY_RANK[items[0].severity]);
        var severity = maesterFirst ? severityName(maester[0].test.severity) : items[0].severity;
        var top = maesterFirst ? "Maester " + maester[0].testId + " · " + (maester[0].test.title || "") : items[0].label;
        var text = count + (count === 1 ? " finding" : " findings");
        return '<button type="button" class="pai-fsum' + (compact ? " pai-fmini" : "") + '" data-findings-more="' + esc(object.objectId) + '" title="' + esc(text + " - most severe: " + top) + '">' +
            '<span class="pai-fsum-head"><span class="pai-sev ' + severityClass(severity) + '">' + esc(severity) + '</span><span class="pai-fcount">' + esc(text) + "</span></span>" +
            (compact ? "" : '<span class="pai-ftop">' + esc(top) + "</span>") + "</button>";
    }

    // A filter pill with the number of items it would show; facets is the filter state it belongs to.
    function renderFacets() {
        var typeCounts = {}, typeTotal = 0, subCounts = {}, subTotal = 0, tierCounts = {}, tierTotal = 0;
        objects.forEach(function (object) {
            if (matches(object, "type")) { typeTotal++; typeCounts[object.objectType] = (typeCounts[object.objectType] || 0) + 1; }
            if (filters.type && object.objectType === filters.type && object.objectSubType && matches(object, "subType")) { subTotal++; subCounts[object.objectSubType] = (subCounts[object.objectSubType] || 0) + 1; }
            if (matches(object, "tier")) { tierTotal++; var tier = effectiveTier(object); tierCounts[tier] = (tierCounts[tier] || 0) + 1; }
        });
        var pill = function (facet, value, label, count, options) { return EntraOpsFilters.pill(filters, facet, value, label, count, options); };
        $("paiTypePills").innerHTML = pill("type", "", "All", typeTotal) + OBJECT_TYPES.filter(function (type) { return objects.some(function (object) { return object.objectType === type; }); }).map(function (type) {
            return pill("type", type, TYPE_PLURAL[type], typeCounts[type] || 0, { icon: TYPE_ICON[type] });
        }).join("");
        var subTypes = filters.type ? Array.from(new Set(objects.filter(function (object) { return object.objectType === filters.type && object.objectSubType; }).map(function (object) { return object.objectSubType; }))).sort() : [];
        $("paiSubTypeRow").hidden = subTypes.length < 2 && !filters.subType;
        $("paiSubTypePills").innerHTML = pill("subType", "", "All " + (TYPE_PLURAL[filters.type] || "").toLowerCase(), subTotal) + subTypes.map(function (subType) {
            return pill("subType", subType, subType.replace(/([a-z])([A-Z])/g, "$1 $2"), subCounts[subType] || 0);
        }).join("");
        $("paiTierPills").innerHTML = pill("tier", "", "All", tierTotal) + TIERS.concat(["Unclassified"]).filter(function (tier) {
            return tier !== "WorkloadPlane" || tierCounts[tier] || filters.tier === tier;
        }).map(function (tier) {
            return EntraOpsFilters.tierPill(filters, "tier", tier, TIER_LABEL[tier], tierCounts[tier] || 0);
        }).join("");
        var more = MORE_FILTERS.filter(function (key) { return filters[key]; }).length;
        $("paiMoreFilterCount").hidden = !more;
        $("paiMoreFilterCount").textContent = String(more);
    }

    function maesterChip(finding, objectId) {
        var test = finding.test;
        var tip = finding.testId + " (" + maesterSeverityLabel(test) + "): " + (test.title || "") + " - select for details";
        return '<button type="button" class="chip pai-finding pai-maester ' + maesterSeverityClass(test) + '" data-maester-open="' + esc(finding.testId) + '" data-maester-object="' + esc(objectId) + '" title="' + esc(tip) + '">' +
            '<span class="pai-maester-mark">Maester</span>' + breakable(finding.testId) + "</button>";
    }

    function maesterFilterOptions() {
        if (!MAESTER) return [];
        var ids = Object.keys(MAESTER_TESTS).sort(function (a, b) { return maesterRank(MAESTER_TESTS[a]) - maesterRank(MAESTER_TESTS[b]) || a.localeCompare(b); });
        return [{ value: "__maester", label: "Any Maester finding" }].concat(ids.map(function (id) { return { value: "maester:" + id, label: "Maester " + id + " - " + String(MAESTER_TESTS[id].title || "").slice(0, 70) }; }));
    }

    function renderInventory() {
        var list = filteredObjects();
        var pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
        if (state.page >= pages) state.page = pages - 1;
        var pageItems = list.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
        $("paiResultCount").textContent = list.length + " of " + objects.length + " objects";
        renderFacets();
        $("paiTableBody").innerHTML = pageItems.map(function (object) {
            var entry = state.worklistEntries[object.objectId];
            var status = worklistStatus(object.objectId);
            var tier = TIER_LABEL[object.tierName] ? object.tierName : "Unclassified";
            var target = entry && entry.adminTierLevelName !== tier ? '<div class="pai-small">Target: ' + tierBadge(entry.adminTierLevelName) + "</div>" : (entry ? '<div class="pai-small muted">In worklist</div>' : "");
            var units = (object.administrativeUnits || []).map(function (unit) {
                return '<span class="chip pai-unit" title="' + esc(unit.displayName || unit.id) + '">' + breakable(unit.displayName || unit.id) + "</span>";
            }).join("");
            return '<tr data-object="' + esc(object.objectId) + '">' +
                '<td class="pai-col-check"><input type="checkbox" data-select="' + esc(object.objectId) + '"' + (state.selected.has(object.objectId) ? " checked" : "") + ' aria-label="Select ' + esc(object.displayName) + '" /></td>' +
                '<td><button type="button" class="pai-link" data-open="' + esc(object.objectId) + '">' + esc(object.displayName) + '</button><div class="muted pai-small cell-truncate" title="' + esc(object.userPrincipalName || object.objectId) + '">' + esc(object.userPrincipalName || object.objectId) + "</div>" + findingsSummary(object, true) + "</td>" +
                "<td>" + esc(typeLabel(object.objectType)) + '<div class="muted pai-small">' + breakable(object.objectSubType, true) + "</div></td>" +
                "<td>" + tierBadge(tier) + target + (status && status !== "Unchanged" ? ' <span class="status-chip ' + (status === "Added" ? "added" : status === "Removed" ? "removed" : "modified") + '">' + esc(status) + "</span>" : "") + "</td>" +
                "<td>" + assignmentCell(object) + "</td>" +
                "<td>" + relationshipCell(object) + "</td>" +
                "<td>" + (units ? '<div class="pai-units">' + units + "</div>" : '<span class="muted">None</span>') + "</td>" +
                '<td class="pai-findings-cell">' + findingsSummary(object) + "</td></tr>";
        }).join("") || '<tr><td colspan="8" class="muted">No objects match the current filters.</td></tr>';

        $("paiPager").innerHTML = pages > 1 ? '<button type="button" class="btn small" data-page="-1"' + (state.page === 0 ? " disabled" : "") + '>&lsaquo; Previous</button><span>Page ' + (state.page + 1) + " of " + pages + '</span><button type="button" class="btn small" data-page="1"' + (state.page >= pages - 1 ? " disabled" : "") + ">Next &rsaquo;</button>" : "";
        $("paiSelectAll").checked = list.length > 0 && list.every(function (object) { return state.selected.has(object.objectId); });
        $("paiSelectionCount").textContent = state.selected.size + " selected";
        $("paiBulk").classList.toggle("active", state.selected.size > 0);
        document.querySelectorAll("#paiTable thead th[data-sort]").forEach(function (th) {
            th.setAttribute("aria-sort", th.getAttribute("data-sort") === state.sort ? (state.sortDir === 1 ? "ascending" : "descending") : "none");
        });
    }

    function highestAssignmentsCell(object) {
        if (!object) return '<span class="muted">-</span>';
        var highest = object.assignmentSummary.highestTierName;
        var matching = (object.assignments || []).filter(function (assignment) { return assignment.tierName === highest; });
        if (!matching.length) return '<span class="muted">No classified role assignments</span>';
        var roles = matching.slice(0, 3).map(function (assignment) {
            return '<li><a class="cell-link" href="../EamDashboard/index.html#assignment=' + encodeURIComponent(assignment.id) + '">' + esc(assignment.roleDefinitionName || assignment.roleDefinitionId) + '</a> <span class="muted pai-small">' + esc([assignment.roleSystem, assignment.scopeName, assignment.pimAssignmentType, assignment.transitiveBy ? "via " + assignment.transitiveBy : ""].filter(Boolean).join(" · ")) + "</span></li>";
        });
        if (matching.length > 3) roles.push('<li><button type="button" class="pai-link pai-small" data-open="' + esc(object.objectId) + '">+' + (matching.length - 3) + " more</button></li>");
        return tierBadge(highest) + '<ul class="pai-role-list">' + roles.join("") + "</ul>";
    }

    function worklistStatusChip(status) {
        var cls = status === "Added" ? "added" : status === "Removed" ? "removed" : status === "Changed" ? "modified" : "unchanged";
        return '<span class="status-chip ' + cls + '">' + esc(status === "Unchanged" ? "In repository file" : status) + "</span>";
    }

    function renderWorklistMeta() {
        var pending = pendingChanges();
        $("paiWorklistMeta").textContent = Object.keys(state.worklistEntries).length + " entries · " + (pending.Added + pending.Changed + pending.Removed) + " pending changes";
    }

    function renderWorklist() {
        $("paiFileChanged").hidden = !(FILE_ENABLED && state.fileChanged);
        var ids = Array.from(new Set(Object.keys(state.worklistEntries).concat(Object.keys(fileEntries))));
        ids.sort(function (a, b) {
            var left = (state.worklistEntries[a] || fileEntries[a]).objectDisplayName || a, right = (state.worklistEntries[b] || fileEntries[b]).objectDisplayName || b;
            return left.localeCompare(right);
        });
        renderWorklistMeta();
        $("paiWorklistBody").innerHTML = ids.map(function (id) {
            var entry = state.worklistEntries[id] || fileEntries[id];
            var status = worklistStatus(id);
            var object = objectsById[id];
            var current = object ? (TIER_LABEL[object.tierName] ? object.tierName : "Unclassified") : "";
            var name = object ? '<button type="button" class="pai-link" data-open="' + esc(id) + '">' + esc(object.displayName) + "</button>" : esc(entry.objectDisplayName || id) + ' <span class="chip warn" title="The object is not part of the current Privileged EAM export.">Not in export</span>';
            var editable = status !== "Removed";
            var target = editable ? '<select class="pai-input" data-target-tier="' + esc(id) + '" aria-label="Target tier">' + TIERS.map(function (tier) {
                return '<option value="' + tier + '"' + (tier === entry.adminTierLevelName ? " selected" : "") + ">" + esc(TIER_LABEL[tier]) + "</option>";
            }).join("") + "</select>" : tierBadge(entry.adminTierLevelName);
            var justification = editable ? '<input type="text" class="pai-input pai-justification" maxlength="200" data-justification="' + esc(id) + '" value="' + esc(entry.justification || "") + '" aria-label="Justification" />' : esc(entry.justification || "");
            return '<tr class="' + (status === "Removed" ? "pai-removed" : "") + '" data-worklist="' + esc(id) + '"><td>' + name + '<div class="muted pai-small cell-truncate" title="' + esc(id) + '">' + esc(id) + "</div></td>" +
                "<td>" + esc(typeLabel(entry.objectType) || "-") + (object && object.objectSubType ? '<div class="muted pai-small">' + esc(object.objectSubType) + "</div>" : "") + "</td>" +
                "<td>" + (current ? tierBadge(current) : '<span class="muted">-</span>') + "</td>" +
                "<td>" + highestAssignmentsCell(object) + "</td>" +
                "<td>" + target + "</td>" +
                '<td class="pai-wrap">' + justification + "</td>" +
                "<td>" + worklistStatusChip(status) + "</td>" +
                "<td>" + (status === "Removed" ? '<button type="button" class="btn small" data-restore="' + esc(id) + '">Restore</button>' : '<button type="button" class="btn small" data-remove="' + esc(id) + '">Remove</button>') + "</td></tr>";
        }).join("") || '<tr><td colspan="8" class="muted">The worklist is empty. Add objects above, select objects in the Overview and set a target tier, or import a CSV / JSON file.</td></tr>';

        var file = SETTINGS.objectClassificationFile || {};
        var sources = [];
        if (CSA_ENABLED) sources.push("custom security attributes");
        if (ALTERNATE_TYPE_LABELS.length) sources.push("Alternate Tier Level Attributes for " + esc(ALTERNATE_TYPE_LABELS.join(", ")));
        if (FILE_ENABLED) sources.push("Object Classification File <code>" + esc(file.filePath || "./Classification/ObjectClassification.json") + "</code> with " + Object.keys(fileEntries).length + " valid entries");
        var status = sources.length ? "<b>Classification sources:</b> " + sources.join("; ") + ". " : "<b>No classification source is enabled</b> in EntraOpsConfig.json - all objects stay Unclassified. ";
        if (sources.length > 1) status += "They are used in this order: an object without a tier in one source is classified by the next. ";
        if (CSA_ENABLED) status += "Generate the PowerShell script below to set the tier custom security attributes. ";
        if (FILE_ENABLED) status += "Download the file and commit it to the repository to apply the worklist with the next Privileged EAM pull" + (sources.length > 1 ? " - file entries only apply to objects that the other sources don't classify" : "") + ". ";
        if (!FILE_ENABLED && !CSA_ENABLED) status += "Target tiers can't be applied from this page: adjust the filters, or enable the Object Classification File or custom security attributes in EntraOpsConfig.json or the Configuration Wizard. Export the worklist as CSV to share it. ";
        $("paiFileStatus").innerHTML = status + "The worklist is stored in this browser only." +
            (FILE_ENABLED && file.error ? '<br><span class="pai-error">The repository file could not be loaded: ' + esc(file.error) + "</span>" : "");

        var foreign = crossTenantScriptObjects();
        $("paiScriptCrossTenant").hidden = !foreign.length;
        $("paiScriptCrossTenant").innerHTML = foreign.length ? "<b>" + foreign.length + " object(s) not included in the script:</b> they belong to another tenant, and custom security attributes can only be set on objects of the home tenant" +
            (DATA.homeTenantId ? " (" + esc(DATA.homeTenantId) + ")" : "") + ".<ul>" + foreign.map(function (object) {
                return "<li>" + esc(object.displayName) + " - " + esc(typeLabel(object.objectType)) + ", tenant " + esc(object.objectTenantId || "unknown") + "</li>";
            }).join("") + "</ul>" : "";
    }

    // Where the object comes from (OriginType, OriginTenantId and OriginId of the Privileged EAM export, EntraOps 1.2.0 or
    // later): the tenant and ID only where they differ from the object's own.
    var ORIGIN_LABEL = {
        Cloud: "Cloud", OnPremises: "Active Directory", CrossTenantSync: "Cross-tenant synchronization",
        B2BInvitation: "Invited guest", TenantGovernance: "Tenant Governance", InternalApplication: "Application of this tenant",
        ExternalApplication: "Application of another organization", FirstPartyApplication: "Microsoft application"
    };
    function originText(object) {
        if (!object.originType) return "";
        var parts = [esc(ORIGIN_LABEL[object.originType] || object.originType)];
        if (object.originTenantId && String(object.originTenantId).toLowerCase() !== String(object.objectTenantId || "").toLowerCase()) {
            parts.push('<span class="muted">tenant <span class="cell-mono">' + esc(object.originTenantId) + "</span></span>");
        }
        if (object.originId && object.originId !== object.objectId && object.originId !== object.userPrincipalName) {
            parts.push('<span class="muted">ID <span class="cell-mono">' + esc(object.originId) + "</span></span>");
        }
        return parts.join(" · ");
    }

    // The object itself is in another tenant. isForeign also covers guests and the service principals of multi-tenant
    // applications, which are objects of the home tenant; data of an older generator only has isForeign, with this meaning.
    function inOtherTenant(object) {
        return typeof object.isObjectOfOtherTenant === "boolean" ? object.isObjectOfOtherTenant : !!object.isForeign;
    }

    // Worklist changes the script would make on objects of other tenants, which can't be modified from the home tenant.
    function crossTenantScriptObjects() {
        return Object.keys(state.worklistEntries).sort().map(function (id) { return objectsById[id]; }).filter(function (object) {
            return object && inOtherTenant(object) && object.objectType !== "group" &&
                state.worklistEntries[object.objectId].adminTierLevelName !== (TIER_LABEL[object.tierName] ? object.tierName : "Unclassified");
        });
    }

    // Where the findings of the other rules come from, and what is not shown here.
    function renderFindingsNote() {
        var note = $("paiFindingsNote"), parts = [];
        if (savedFindingsState.status === "missing") {
            parts.push("The findings of the other EntraOps finding rules (Privileged EAM, Tier Breach, Privilege History, access drift) are not loaded: " +
                "<code>New-EntraOpsReportingData</code> saves them with the report data (<code>Reports/Findings/data/findings.js</code>).");
        } else if (savedFindingsState.status === "otherTenant") {
            parts.push("The saved findings belong to tenant " + esc(SAVED_FINDINGS.TenantId) + ", not to this inventory, and are not shown.");
        } else {
            var saved = new Date(SAVED_FINDINGS.GeneratedAt), generated = new Date(DATA.generatedAt);
            if (!isNaN(saved) && !isNaN(generated) && generated - saved > 24 * 3600 * 1000) {
                parts.push("The saved findings were evaluated on " + esc(saved.toLocaleDateString()) + ", before this inventory (" + esc(generated.toLocaleDateString()) + "). Generate the report data again to update them.");
            }
            if (savedFindingsState.outside) {
                parts.push(savedFindingsState.outside + " finding(s) of " + savedFindingsState.outsideRules + " rule(s) concern roles, access packages, policies, the tenant or objects outside this inventory - " +
                    'see the <a class="cell-link" href="../PimRequestFlow/index.html">PIM Request Flow</a>, <a class="cell-link" href="../AccessPackageFlow/index.html">Access Package Flow</a> and ' +
                    '<a class="cell-link" href="../ConfigurationAnalyzer/index.html">Configuration Analyzer</a> reports.');
            }
        }
        note.hidden = !parts.length;
        note.innerHTML = parts.map(function (part) { return "<p>" + part + "</p>"; }).join("");
        $("paiWhatIfNote").hidden = !state.whatIf || savedFindingsState.status !== "loaded";
    }

    function renderAll() {
        refreshFindings();
        fillFindingFilter();
        renderStats();
        renderInventory();
        renderWorklist();
        renderFindingsNote();
        renderRules();
    }

    // ---- Views (Overview / Object Classification) -------------------------------------------------
    function methodAllows(element) {
        var method = element.getAttribute("data-classification-method");
        return method === "file" ? FILE_ENABLED : method === "csa" ? CSA_ENABLED : true;
    }

    function viewFromUrl() {
        var view = new URLSearchParams(location.search).get("view");
        return VIEWS[view] ? view : "overview";
    }

    // The Sections navigation lists the sections of the current view only.
    function setView(view, push) {
        if (!VIEWS[view]) view = "overview";
        document.querySelectorAll("[data-view]").forEach(function (element) { element.hidden = element.getAttribute("data-view") !== view || !methodAllows(element); });
        document.querySelectorAll("[data-view-nav]").forEach(function (item) { item.classList.toggle("active", item.getAttribute("data-view-nav") === view); });
        document.querySelectorAll(".nav-item.section-item").forEach(function (item) {
            var target = document.getElementById(item.getAttribute("data-target"));
            var host = target && target.closest("[data-view]");
            item.hidden = !host || host.getAttribute("data-view") !== view || !methodAllows(item) || (target !== host && target.hidden);
        });
        $("paiViewCrumb").textContent = VIEWS[view];
        $("paiViewTitle").textContent = VIEW_TITLES[view];
        if (push && view !== viewFromUrl()) setUrl(location.pathname + (view === "overview" ? "" : "?view=" + view), "push");
    }

    // The view and the open side panel are kept in the URL (?view=, #asset=, #rule=), so Back and deep links restore them.
    var lastUrl = "";
    function setUrl(url, mode) {
        if (!mode) return;
        if (mode === "push") history.pushState(null, "", url); else history.replaceState(null, "", url);
        lastUrl = location.href;
    }

    function applyUrl() {
        if (location.href === lastUrl) return;
        lastUrl = location.href;
        closeRuleBlade(false);
        closeDrawer(false);
        $("paiRuleNotFound").hidden = true;
        setView(viewFromUrl(), false);
        applyDeepLink();
    }

    function addObjectFromInput() {
        var text = $("paiAddObject").value.trim();
        var guid = (text.match(/[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}/i) || [])[0];
        var matches = guid ? [objectsById[guid.toLowerCase()]].filter(Boolean) : objects.filter(function (object) {
            return [object.displayName, object.userPrincipalName].some(function (value) { return value && value.toLowerCase() === text.toLowerCase(); });
        });
        if (matches.length !== 1) {
            showImportResult(matches.length ? "More than one object matches '" + text + "'. Select it from the list or enter its object id." : "No privileged object matches '" + text + "'.", true);
            return;
        }
        var existing = state.worklistEntries[matches[0].objectId];
        setTargetTier([matches[0].objectId], $("paiAddTier").value, existing ? existing.justification : "");
        $("paiAddObject").value = "";
        $("paiImportResult").classList.add("hidden");
        renderAll();
    }

    // ---- Details side panel ---------------------------------------------------------------------
    function relatedList(title, ids, options) {
        options = options || {};
        var values = (ids || []).filter(Boolean);
        if (!values.length) return "";
        var needed = options.object ? requiredLevel(options.object) : null;
        var items = values.map(function (id) {
            var info = relatedInfo(id);
            var label = info.inInventory ? '<button type="button" class="pai-link" data-open="' + esc(info.id) + '">' + esc(info.displayName) + "</button>" : esc(info.displayName);
            var meta = [info.objectType, info.objectSubType].filter(Boolean).join(" · ");
            if (options.devices && info.source === "Microsoft Graph") {
                meta = [info.operatingSystem, info.isCompliant === true ? "compliant" : info.isCompliant === false ? "not compliant" : "", info.isManaged === true ? "managed" : ""].filter(Boolean).join(" · ");
            }
            var tier = info.inInventory ? tierBadge(info.tierName) : '<span class="chip" title="Not listed in the Privileged EAM export">' + (info.source === "Unresolved" ? "Unresolved" : "Not privileged") + "</span>";
            var warning = options.compareTier && needed !== null && relatedLevel(id) > needed ? ' <span class="chip pai-finding sev-high">Lower tier</span>' : "";
            if (options.higherTier && info.inInventory && requiredLevel(objectsById[info.id]) < needed) warning = ' <span class="chip pai-finding sev-high">Higher tier</span>';
            return "<li>" + label + " " + tier + warning + (meta ? '<div class="muted pai-small">' + esc(meta) + "</div>" : "") + (info.inInventory || info.displayName === info.id ? "" : '<div class="muted pai-small">' + esc(info.id) + "</div>") + "</li>";
        });
        return '<details class="drawer-section" open><summary>' + esc(title) + " (" + values.length + ')</summary><ul class="drawer-list pai-related">' + items.join("") + "</ul></details>";
    }

    function assignmentSection(object) {
        var order = function (tier) { return tier in TIER_ORDER ? TIER_ORDER[tier] : TIER_ORDER.Unclassified; };
        var assignments = (object.assignments || []).slice().sort(function (a, b) { return order(a.tierName) - order(b.tierName) || String(a.roleDefinitionName || "").localeCompare(String(b.roleDefinitionName || "")); });
        if (!assignments.length) return "";
        var rows = assignments.map(function (assignment) {
            var via = [assignment.assignmentType, assignment.assignmentSubType].filter(Boolean).join(" - ");
            return "<tr><td><b>" + esc(assignment.roleDefinitionName || assignment.roleDefinitionId) + '</b><div class="muted pai-small">' + esc(assignment.roleSystem) + (assignment.scopeName || assignment.scopeId ? " · " + esc(assignment.scopeName || assignment.scopeId) : "") + "</div>" +
                (assignment.transitiveBy ? '<div class="muted pai-small">Through ' + esc(assignment.transitiveBy) + "</div>" : "") + "</td>" +
                "<td>" + tierBadge(assignment.tierName) + '<div class="muted pai-small">' + esc((assignment.services || []).join(", ")) + "</div></td>" +
                "<td>" + esc(assignment.pimAssignmentType || "-") + '<div class="muted pai-small">' + esc(via) + "</div></td>" +
                '<td><a class="cell-link" href="../EamDashboard/index.html#assignment=' + encodeURIComponent(assignment.id) + '">EAM Dashboard &#8599;</a></td></tr>';
        }).join("");
        var bySystem = Object.keys(object.assignmentSummary.bySystem || {}).map(function (system) { return '<span class="chip">' + esc(system) + " " + object.assignmentSummary.bySystem[system] + "</span>"; }).join(" ");
        return '<details class="drawer-section" open><summary>Role assignments (' + assignments.length + ')</summary><div class="pai-drawer-pad">' + bySystem +
            '<table class="grid-table pai-drawer-table"><thead><tr><th class="no-sort">Role</th><th class="no-sort">Classification</th><th class="no-sort">Assignment</th><th class="no-sort"></th></tr></thead><tbody>' + rows + "</tbody></table></div></details>";
    }

    // urlMode: "push" or "replace" writes #asset= to the URL, false leaves the URL as it is.
    function openDrawer(id, urlMode) {
        var object = objectsById[String(id || "").toLowerCase()];
        if (!object) return;
        var entry = state.worklistEntries[object.objectId], file = fileEntries[object.objectId];
        var tier = TIER_LABEL[object.tierName] ? object.tierName : "Unclassified";
        var kv = function (label, value) { return value === "" || value == null ? "" : "<dt>" + esc(label) + "</dt><dd>" + value + "</dd>"; };
        var identity = kv("Object ID", '<span class="cell-mono">' + esc(object.objectId) + "</span>") +
            kv("Type", esc(typeLabel(object.objectType)) + (object.objectSubType ? " · " + esc(object.objectSubType) : "")) +
            kv(object.objectType === "user" ? "User principal name" : "App id / sign-in name", esc(object.userPrincipalName)) +
            kv("Tenant", esc(object.objectTenantId) + (inOtherTenant(object) ? ' <span class="chip warn">Outside home tenant</span>' : object.isForeign ? ' <span class="chip warn">' + (object.objectType === "user" ? "Guest or external user" : "Application of another organization") + '</span>' : "")) +
            kv("Sync source", object.onPremSynchronized ? "Synchronized (hybrid)" : "Cloud-only") +
            kv("Origin", originText(object)) +
            kv("RBAC systems", esc((object.roleSystems || []).join(", "))) +
            kv("Restricted management", esc(object.restrictedManagement) + '<div class="muted pai-small">Directory role: ' + (object.restrictedManagementByAadRole ? "yes" : "no") + " · Role-assignable group: " + (object.restrictedManagementByRAG ? "yes" : "no") + " · RMAU: " + (object.restrictedManagementByRMAU ? "yes" : "no") + "</div>");
        var classification = kv("Object tier", tierBadge(tier) + (object.tierLevel ? ' <span class="muted">level ' + esc(object.tierLevel) + "</span>" : "")) +
            kv("Highest role assignment tier", tierBadge(object.assignmentSummary.highestTierName)) +
            // The access tier of the findings leaves out delegated permissions (they act within the rights of the signed-in user).
            (object.assignmentSummary.highestAccessTierName && object.assignmentSummary.highestAccessTierName !== object.assignmentSummary.highestTierName ?
                kv("Access tier without delegated permissions", tierBadge(object.assignmentSummary.highestAccessTierName)) : "") +
            kv("Assignments by tier", TIERS.concat(["Unclassified"]).filter(function (t) { return object.assignmentSummary.byTier[t]; }).map(function (t) { return esc(TIER_LABEL[t]) + ": " + object.assignmentSummary.byTier[t]; }).join(" · ") || "None") +
            kv("Object Classification File", file ? tierBadge(file.adminTierLevelName) + (file.justification ? '<div class="muted pai-small">' + esc(file.justification) + "</div>" : "") : '<span class="muted">No entry</span>') +
            kv("Worklist target", entry ? tierBadge(entry.adminTierLevelName) + ' <span class="status-chip">' + esc(worklistStatus(object.objectId)) + "</span>" : '<span class="muted">Not in worklist</span>');
        var actions = '<div class="pai-drawer-actions">' +
            '<a class="btn small" href="../EamDashboard/index.html#asset=' + encodeURIComponent(object.objectId) + '">Open in EAM Dashboard &#8599;</a>' +
            '<a class="btn small" href="../AccessPathMap/index.html#node=' + encodeURIComponent(object.objectId.toUpperCase()) + '">Show in Access Path Map &#8599;</a>' +
            '<a class="btn small" href="../TierBreachAnalyzer/index.html">Tier Breach Analyzer &#8599;</a></div>' +
            '<div class="pai-drawer-actions"><select class="pai-input" id="paiDrawerTier" aria-label="Target tier">' + TIERS.map(function (t) { return '<option value="' + t + '"' + ((entry ? entry.adminTierLevelName : tier) === t ? " selected" : "") + ">" + esc(TIER_LABEL[t]) + "</option>"; }).join("") + "</select>" +
            '<input type="text" class="pai-input pai-justification" id="paiDrawerJustification" maxlength="200" placeholder="Justification" value="' + esc(entry ? entry.justification : "") + '" />' +
            '<button type="button" class="btn small primary" id="paiDrawerSet">Set target tier</button>' +
            (entry ? '<button type="button" class="btn small" id="paiDrawerRemove">Remove from worklist</button>' : "") + "</div>";

        $("paiDrawerTitle").innerHTML = esc(object.displayName) + " " + tierBadge(tier);
        $("paiDrawerBody").innerHTML = actions +
            '<details class="drawer-section" open><summary>Identity</summary><dl class="kv">' + identity + "</dl></details>" +
            '<details class="drawer-section" open><summary>Classification</summary><dl class="kv">' + classification + "</dl></details>" +
            findingsDrawerSection(object) +
            expiredExceptionDrawerSection(object) +
            maesterDrawerSection(object) +
            relatedList("Owners", object.owners, { object: object, compareTier: true }) +
            relatedList("Sponsors", object.sponsors, { object: object }) +
            relatedList("Owned objects", object.ownedObjects, { object: object, higherTier: true }) +
            relatedList("Owned devices", object.ownedDevices, { devices: true }) +
            relatedList("Identity parent", object.identityParent ? [object.identityParent] : [], { object: object, compareTier: true }) +
            relatedList("Associated work account", object.associatedWorkAccount) +
            relatedList("Associated PAW device", object.associatedPawDevice, { devices: true }) +
            ((object.administrativeUnits || []).length ? '<details class="drawer-section" open><summary>Administrative units (' + object.administrativeUnits.length + ')</summary><ul class="drawer-list pai-related">' + object.administrativeUnits.map(function (unit) { return "<li>" + esc(unit.displayName || unit.id) + '<div class="muted pai-small">' + esc(unit.id) + "</div></li>"; }).join("") + "</ul></details>" : "") +
            assignmentSection(object);

        $("paiDrawerSet").addEventListener("click", function () {
            setTargetTier([object.objectId], $("paiDrawerTier").value, $("paiDrawerJustification").value);
            renderAll();
            openDrawer(object.objectId, false);
        });
        if ($("paiDrawerRemove")) $("paiDrawerRemove").addEventListener("click", function () {
            removeFromWorklist([object.objectId]);
            renderAll();
            openDrawer(object.objectId, false);
        });
        showPanel("paiDrawer", "paiDrawerBackdrop");
        setUrl(location.pathname + location.search + "#asset=" + encodeURIComponent(object.objectId), urlMode);
    }

    // Findings of an object that were accepted at the last evaluation and whose exception has expired since: listed
    // apart from the findings above, whose status and counts are those of the last evaluation.
    function expiredExceptionDrawerSection(object) {
        if (state.whatIf) return "";
        var id = String(object.objectId || "").toLowerCase();
        var entries = [];
        SAVED_RULES.forEach(function (rule) {
            (rule.acceptedResults || []).forEach(function (result) {
                if (String(result.objectId || "").toLowerCase() === id && acceptanceExpired(result)) entries.push({ rule: rule, result: result });
            });
        });
        if (!entries.length) return "";
        return '<details class="drawer-section" id="paiDrawerExpired" open><summary>Exception expired (' + entries.length + ')</summary><div class="pai-drawer-pad">' +
            '<div class="muted pai-small">These findings count again at the next evaluation. Generate the report data again, or accept them again in the Findings view.</div>' +
            '<ul class="drawer-list pai-flist">' + entries.map(function (entry) {
                var rule = entry.rule;
                return '<li class="pai-fitem"><div class="pai-fitem-head"><span class="pai-sev ' + severityClass(rule.severity) + '">' + esc(rule.severity) + "</span><b>" + esc(rule.title) + "</b>" +
                    (rule.id ? '<span class="pai-rule-id">' + esc(rule.id) + "</span>" : "") +
                    ' <span class="chip warn pai-exception-state pai-exception-expired">Exception expired ' + esc(String(entry.result.exception.ExpiresOn || "").slice(0, 10)) + "</span></div>" +
                    (entry.result.message ? '<ul class="pai-fmessages"><li>' + esc(entry.result.message) + "</li></ul>" : "") +
                    (ruleById[rule.id] ? '<div class="muted pai-small"><button type="button" class="pai-link pai-small" data-rule-open="' + esc(rule.id) + '">All affected objects</button></div>' : "") + "</li>";
            }).join("") + "</ul></div></details>";
    }

    // The findings of an object grouped by category, with the results of the rule and the report that shows them.
    function findingsDrawerSection(object) {
        var items = object._items;
        if (!items.length) return "";
        var html = categoryGroups(items, function (item) { return item.rule; }).map(function (group) {
            return '<div class="pai-fgroup"><div class="pai-fgroup-title">' + esc(group.title) + '</div><ul class="drawer-list pai-flist">' + group.entries.map(function (item) {
                var rule = item.rule;
                var area = AREA_INFO[rule.area] || { label: rule.area };
                var messages = item.results.slice(0, MAX_RESULT_MESSAGES).map(function (result) { return "<li>" + esc(result.message) + findingLinksHtml(rule, result, true) + "</li>"; }).join("") +
                    (item.results.length > MAX_RESULT_MESSAGES ? '<li class="muted">+' + (item.results.length - MAX_RESULT_MESSAGES) + " more</li>" : "");
                // The source, and the report that shows the details when it has another name.
                var source = area.href ? (area.report !== area.label ? esc(area.label) + " · " : "") + '<a class="cell-link" href="' + esc(area.href(object)) + '">' + esc(area.report) + " &#8599;</a>" : esc(area.label);
                return '<li class="pai-fitem"><div class="pai-fitem-head"><span class="pai-sev ' + severityClass(item.severity) + '">' + esc(item.severity) + "</span><b>" + esc(item.label) + "</b>" +
                    (rule.id ? '<span class="pai-rule-id" title="' + esc(rule.maesterTestId ? "Maester test " + rule.maesterTestId : "EntraOps check") + '">' + esc(rule.id) + "</span>" : "") + "</div>" +
                    (rule.description ? '<div class="muted pai-small pai-pre">' + esc(rule.description) + "</div>" : "") +
                    (messages ? '<ul class="pai-fmessages">' + messages + "</ul>" : "") +
                    '<div class="muted pai-small">' + source + (rule.area === "PrivilegedAssets" && state.whatIf ? " · What-if" : "") +
                    (ruleById[rule.id] ? ' · <button type="button" class="pai-link pai-small" data-rule-open="' + esc(rule.id) + '">All affected objects</button>' : "") + "</div></li>";
            }).join("") + "</ul></div>";
        }).join("");
        return '<details class="drawer-section" id="paiDrawerFindings" open><summary>Findings (' + items.length + ')</summary><div class="pai-drawer-pad">' + html + "</div></details>";
    }

    function closeDrawer(updateUrl) {
        closeMaesterBlade(false);
        if (!hidePanel("paiDrawer", "paiDrawerBackdrop")) return;
        if (updateUrl !== false && /^#asset=/.test(location.hash || "")) setUrl(location.pathname + location.search, "replace");
    }

    // ---- Side panels: the object drawer and the Maester and check blades are modal dialogs ------------------
    var PANELS = ["paiRuleBlade", "paiMaesterBlade", "paiDrawer"];
    var panelOpeners = {};

    function panelOpen(id) { return $(id).classList.contains("open"); }

    // Focus returns to the element that opened a panel; an opener in a panel that was closed meanwhile hands over
    // to the opener of that panel.
    function focusTarget(element) {
        for (var depth = 0; element && depth < PANELS.length; depth++) {
            var host = element.closest ? element.closest(".drawer") : null;
            if (!host || panelOpen(host.id)) return document.contains(element) && element.getClientRects().length ? element : null;
            element = panelOpeners[host.id];
        }
        return null;
    }

    function showPanel(id, backdropId) {
        var panel = $(id), wasOpen = panelOpen(id);
        if (!wasOpen) panelOpeners[id] = document.activeElement;
        panel.classList.add("open");
        $(backdropId).classList.add("open");
        panel.setAttribute("aria-hidden", "false");
        panel.inert = false;
        if (!wasOpen || !panel.contains(document.activeElement)) panel.querySelector(".drawer-head .close").focus();
    }

    function hidePanel(id, backdropId) {
        var panel = $(id);
        if (!panelOpen(id)) return false;
        var hadFocus = panel.contains(document.activeElement);
        panel.classList.remove("open");
        $(backdropId).classList.remove("open");
        panel.setAttribute("aria-hidden", "true");
        panel.inert = true;
        var target = hadFocus ? focusTarget(panelOpeners[id]) : null;
        if (target) target.focus();
        return true;
    }

    // Tab and Shift+Tab stay in the topmost open panel.
    function trapFocus(ev) {
        var id = PANELS.filter(panelOpen)[0];
        if (ev.key !== "Tab" || !id) return;
        var panel = $(id);
        var items = Array.from(panel.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea, summary, [tabindex]:not([tabindex="-1"])'))
            .filter(function (element) { return element.getClientRects().length; });
        if (!items.length) return;
        var first = items[0], last = items[items.length - 1], active = document.activeElement;
        if (!panel.contains(active) || (ev.shiftKey && active === first) || (!ev.shiftKey && active === last)) {
            ev.preventDefault();
            (ev.shiftKey ? last : first).focus();
        }
    }

    function applyDeepLink() {
        var rule = /^#rule=(.+)$/.exec(location.hash || "");
        if (rule) {
            var ruleId;
            try { ruleId = decodeURIComponent(rule[1]); } catch (_) { return; }
            // A check opens in the Findings view, also from a link without ?view=findings.
            if (viewFromUrl() !== "findings") {
                setUrl(location.pathname + "?view=findings" + location.hash, "replace");
                setView("findings", false);
            }
            if (!openRuleBlade(ruleId, false)) showRuleNotFound(ruleId);
            return;
        }
        var match = /^#asset=([^&]+)(?:&maester=(.+))?$/.exec(location.hash || "");
        if (!match) return;
        try {
            if (!objectsById[decodeURIComponent(match[1]).toLowerCase()] && window.EntraOpsReportUtils) {
                EntraOpsReportUtils.deepLinkNotFound("Privileged asset", decodeURIComponent(match[1]), "privileged assets");
                return;
            }
            openDrawer(decodeURIComponent(match[1]), false);
            if (match[2]) openMaesterBlade(decodeURIComponent(match[2]), decodeURIComponent(match[1]), false);
        } catch (_) { /* malformed hash */ }
    }

    // ---- Maester finding blade ---------------------------------------------------------------------
    // Small, escaped Markdown subset (headings, lists, tables, bold, code, https links) for Maester descriptions and results.
    function renderMarkdown(text) {
        var inline = function (value) {
            return esc(value)
                .replace(/&lt;br\s*\/?&gt;/gi, "<br>")
                .replace(/`([^`]+)`/g, "<code>$1</code>")
                .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
                .replace(/\[([^\]]+)\]\((https:\/\/[^\s)]+)\)/g, '<a class="cell-link" href="$2" target="_blank" rel="noopener noreferrer">$1 &#8599;</a>');
        };
        var html = [], paragraph = [], items = [], listTag = "", rows = [];
        var flush = function () {
            if (paragraph.length) html.push("<p>" + paragraph.map(inline).join("<br>") + "</p>");
            if (items.length) html.push("<" + listTag + ">" + items.map(function (item) { return "<li>" + inline(item) + "</li>"; }).join("") + "</" + listTag + ">");
            if (rows.length) {
                var cells = function (row, tag) { return "<tr>" + row.map(function (cell) { return "<" + tag + ">" + inline(cell) + "</" + tag + ">"; }).join("") + "</tr>"; };
                html.push('<div class="pai-md-table"><table class="grid-table"><thead>' + cells(rows[0], "th") + "</thead><tbody>" + rows.slice(1).map(function (row) { return cells(row, "td"); }).join("") + "</tbody></table></div>");
            }
            paragraph = []; items = []; rows = []; listTag = "";
        };
        String(text || "").replace(/\r/g, "").split("\n").forEach(function (line) {
            var trimmed = line.trim(), match;
            if (!trimmed) { flush(); return; }
            if (/^\|.*\|$/.test(trimmed)) {
                if (!rows.length) flush();
                if (!/^\|[\s:|-]+\|$/.test(trimmed)) rows.push(trimmed.slice(1, -1).split("|").map(function (cell) { return cell.trim(); }));
                return;
            }
            if ((match = /^(#{1,6})\s+(.*)$/.exec(trimmed))) { flush(); html.push("<h5>" + inline(match[2]) + "</h5>"); return; }
            if ((match = /^(?:[*-]|\d+\.)\s+(.*)$/.exec(trimmed))) {
                var tag = /^\d/.test(trimmed) ? "ol" : "ul";
                if (listTag && listTag !== tag) flush();
                if (!listTag) { flush(); listTag = tag; }
                items.push(match[1]);
                return;
            }
            if (rows.length || items.length) flush();
            paragraph.push(trimmed);
        });
        flush();
        return html.join("");
    }

    function safeHttpsLink(url, label) {
        return /^https:\/\//i.test(String(url || "")) ? '<a class="cell-link" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(label || url) + " &#8599;</a>" : "";
    }

    function maesterDrawerSection(object) {
        var list = object._maester || [];
        if (!list.length) return "";
        var items = list.map(function (finding) {
            return "<li>" + maesterChip(finding, object.objectId) + ' <span class="muted pai-small">' + esc(maesterSeverityLabel(finding.test)) + '</span><div class="muted pai-small">' + esc(finding.test.title) + "</div></li>";
        }).join("");
        return '<details class="drawer-section" id="paiDrawerMaester" open><summary>Maester findings (' + list.length + ')</summary><ul class="drawer-list pai-related">' + items + "</ul></details>";
    }

    var blade = { testId: "", objectId: "" };

    function openMaesterBlade(testId, objectId, updateUrl) {
        var test = maesterTest(testId);
        if (!test) return;
        var object = objectsById[String(objectId || "").toLowerCase()] || null;
        var current = object ? (object._maester || []).filter(function (finding) { return finding.testId === testId; })[0] : null;
        var assets = current ? current.assets : [];
        var sevClass = maesterSeverityClass(test);
        var chip = function (value, extra) { return value ? '<span class="chip' + (extra ? " " + extra : "") + '">' + esc(value) + "</span>" : ""; };
        var kv = function (label, value) { return value === "" || value == null ? "" : "<dt>" + esc(label) + "</dt><dd>" + value + "</dd>"; };
        var mono = function (value) { return value ? '<span class="cell-mono">' + esc(value) + "</span>" : ""; };
        var affected = objects.filter(function (candidate) { return candidate.objectId !== (object && object.objectId) && (candidate._maester || []).some(function (finding) { return finding.testId === testId; }); });
        var affectedTotal = affected.length + (object ? 1 : 0);
        var executed = MAESTER && MAESTER.executedAt ? new Date(MAESTER.executedAt) : null;
        var totals = (MAESTER && MAESTER.totals) || {};

        $("paiMaesterKicker").textContent = "Maester \u00b7 Failed test";
        $("paiMaesterTitle").textContent = test.title || test.name || test.id;
        $("paiMaesterChips").innerHTML = '<span class="chip pai-finding ' + sevClass + '">' + esc(maesterSeverityLabel(test)) + " severity</span>" +
            chip(test.id, "brand") + chip(test.result || "Failed", "priv") + chip(test.block) + chip(test.service);
        $("paiMaesterBlade").className = "drawer pai-blade " + sevClass + (panelOpen("paiMaesterBlade") ? " open" : "");

        var stats = [
            ["Severity", esc(maesterSeverityLabel(test))],
            ["Affected assets on object", object ? String(assets.length) : "-"],
            ["Privileged objects affected", String(affectedTotal)],
            ["Failed in Maester run", esc(String(totals.failed != null ? totals.failed : "-")) + (totals.total ? ' <span class="muted pai-small">of ' + esc(String(totals.total)) + "</span>" : "")]
        ].map(function (stat) { return '<div class="pai-blade-stat"><div class="pai-blade-stat-label">' + esc(stat[0]) + '</div><div class="pai-blade-stat-value">' + stat[1] + "</div></div>"; }).join("");

        var actions = /^https:\/\//i.test(test.helpUrl || "") ? '<a class="btn small primary" href="' + esc(test.helpUrl) + '" target="_blank" rel="noopener noreferrer">Maester test documentation &#8599;</a>' : "";
        assets.forEach(function (asset) {
            if (/^https:\/\//i.test(asset.portalLink || "")) actions += ' <a class="btn small" href="' + esc(asset.portalLink) + '" target="_blank" rel="noopener noreferrer">Open ' + esc(asset.displayName || asset.type || "object") + " in portal &#8599;</a>";
        });
        if (object) actions += ' <button type="button" class="btn small" data-open="' + esc(object.objectId) + '">Show privileged object</button>';

        var assetSections = assets.map(function (asset, index) {
            return '<details class="drawer-section" open><summary>Affected object' + (assets.length > 1 ? " " + (index + 1) + " of " + assets.length : "") + '</summary><dl class="kv">' +
                kv("System", esc(asset.system)) + kv("Anchor kind", esc(asset.anchorKind)) + kv("Type", esc(asset.type)) +
                kv("Id", mono(asset.id)) + kv("Unique id", mono(asset.uniqueId)) + kv("Display name", esc(asset.displayName)) +
                kv("User principal name", esc(asset.userPrincipalName)) + kv("Portal link", safeHttpsLink(asset.portalLink, "Open in portal")) +
                kv("Sources", (asset.sources || []).map(function (source) { return chip(source); }).join(" ")) +
                kv("Failed tests", (asset.tests || []).filter(maesterTest).map(function (id) { return '<button type="button" class="chip pai-finding pai-maester ' + maesterSeverityClass(maesterTest(id)) + '" data-maester-open="' + esc(id) + '" data-maester-object="' + esc(object.objectId) + '">' + breakable(id) + "</button>"; }).join(" ")) +
                "</dl></details>";
        }).join("");

        var others = affected.slice(0, MAESTER_OTHER_OBJECTS).map(function (candidate) {
            return '<li><button type="button" class="pai-link" data-open="' + esc(candidate.objectId) + '">' + esc(candidate.displayName) + "</button> " + tierBadge(effectiveTier(candidate)) +
                '<div class="muted pai-small">' + esc([typeLabel(candidate.objectType), candidate.objectSubType].filter(Boolean).join(" \u00b7 ")) + "</div></li>";
        }).join("");
        if (affected.length > MAESTER_OTHER_OBJECTS) others += '<li class="muted pai-small">+' + (affected.length - MAESTER_OTHER_OBJECTS) + " more privileged objects</li>";

        var siblings = object ? (object._maester || []).filter(function (finding) { return finding.testId !== testId; }) : [];

        $("paiMaesterBody").innerHTML = '<div class="pai-blade-stats">' + stats + '</div><div class="pai-drawer-actions">' + actions + "</div>" +
            (test.description ? '<details class="drawer-section" open><summary>Description and remediation</summary><div class="pai-md pai-drawer-pad">' + renderMarkdown(test.description) + "</div></details>" : "") +
            (test.testResult ? '<details class="drawer-section" open><summary>Test result</summary><div class="pai-md pai-md-scroll pai-drawer-pad">' + renderMarkdown(test.testResult) + "</div></details>" : "") +
            assetSections +
            '<details class="drawer-section" open><summary>Test details</summary><dl class="kv">' +
            kv("Index", esc(test.index)) + kv("Test id", mono(test.id)) + kv("Name", esc(test.name)) + kv("Title", esc(test.title)) +
            kv("Severity", '<span class="chip pai-finding ' + sevClass + '">' + esc(maesterSeverityLabel(test)) + "</span>") + kv("Result", esc(test.result)) +
            kv("Block", esc(test.block)) + kv("Service", esc(test.service)) + kv("Tags", (test.tags || []).map(function (tag) { return chip(tag); }).join(" ")) +
            kv("Documentation", safeHttpsLink(test.helpUrl, test.helpUrl)) + "</dl></details>" +
            (siblings.length ? '<details class="drawer-section" open><summary>Other Maester findings on this object (' + siblings.length + ')</summary><ul class="drawer-list pai-related">' + siblings.map(function (finding) {
                return "<li>" + maesterChip(finding, object.objectId) + '<div class="muted pai-small">' + esc(finding.test.title) + "</div></li>";
            }).join("") + "</ul></details>" : "") +
            (others ? '<details class="drawer-section" open><summary>Other privileged objects with this finding (' + affected.length + ')</summary><ul class="drawer-list pai-related">' + others + "</ul></details>" : "") +
            (MAESTER ? '<details class="drawer-section"><summary>Maester run</summary><dl class="kv">' +
                kv("Result file", mono(MAESTER.sourceFile)) + kv("Executed at", executed && !isNaN(executed) ? esc(executed.toLocaleString()) : esc(MAESTER.executedAt)) +
                kv("Tenant", esc([MAESTER.tenantName, MAESTER.tenantId].filter(Boolean).join(" \u00b7 "))) +
                kv("Tests", esc([totals.passed != null ? totals.passed + " passed" : "", totals.failed != null ? totals.failed + " failed" : "", totals.skipped != null ? totals.skipped + " skipped" : ""].filter(Boolean).join(" \u00b7 "))) +
                kv("Affected objects", esc(MAESTER.affectedObjectCount) + (MAESTER.matchedObjectCount != null ? ' <span class="muted">(' + esc(MAESTER.matchedObjectCount) + " matched to privileged objects)</span>" : "")) +
                "</dl></details>" : "");

        blade.testId = testId;
        blade.objectId = object ? object.objectId : "";
        $("paiMaesterBody").scrollTop = 0;
        showPanel("paiMaesterBlade", "paiMaesterBackdrop");
        if (updateUrl && object) setUrl(location.pathname + location.search + "#asset=" + encodeURIComponent(object.objectId) + "&maester=" + encodeURIComponent(testId), "replace");
    }

    function closeMaesterBlade(updateUrl) {
        if (!hidePanel("paiMaesterBlade", "paiMaesterBackdrop")) return;
        if (updateUrl !== false && blade.objectId) setUrl(location.pathname + location.search + "#asset=" + encodeURIComponent(blade.objectId), "replace");
    }

    // ---- Findings view: the findings of the checks by category ----------------------------------------------
    var STATUS_ICON = { Failed: "✕", Error: "!", Passed: "✓", Skipped: "–", Excluded: "⊘" };
    // AdminTierLevel of a result (0/1/2, see ConvertTo-EntraOpsAdminTierLevel) for objects outside the inventory.
    var LEVEL_TIER = ["ControlPlane", "ManagementPlane", "UserAccess"];
    // Objects (result groups) listed in the panel of a check before "Show all".
    var MAX_RULE_GROUPS = 100;
    var MAESTER_PACK_TESTS = "https://github.com/Cloud-Architekt/EntraOps-MaesterPack/blob/main/tests/";
    var ruleFilters = { search: "", status: "", severity: "", category: "" };
    var rules = [];
    // Without prototype: a check ID of a deep link like "constructor" or "__proto__" is not a check.
    var ruleById = Object.create(null);
    var rulesSource = "none";
    var ruleBlade = newRuleBlade("");

    // State of the open check panel: search, toggles, expanded object groups, the result of the open accept form and
    // the results selected for a bulk exception.
    function newRuleBlade(ruleId) {
        return { ruleId: ruleId, showAll: false, search: "", showUnclassified: false, showAccepted: false, acceptFor: "", expanded: Object.create(null), selected: Object.create(null), bulkOpen: false };
    }

    // A check by its ID, also with another casing (EO.1001 / eo.1001).
    function findRule(ruleId) {
        var id = String(ruleId || "");
        if (ruleById[id]) return ruleById[id];
        var upper = id.toUpperCase();
        return ruleById[upper] || rules.filter(function (rule) { return rule.id.toUpperCase() === upper; })[0] || null;
    }
    // Collapsed categories of the check list (category keys), kept in localStorage across runs and reports.
    var ruleGroups = EntraOpsFilters.collapsible("entraops.privilegedAssets.findings.collapsedCategories", renderRules);
    var visibleCategories = [];

    function objectResult(object) {
        return { objectId: object.objectId, rawObjectId: object.objectId, objectType: object.objectType, displayName: object.displayName, adminTierLevel: null, message: "", evidence: {} };
    }

    // The saved results of all checks; without them (or of another tenant) the Privileged Assets checks of the data
    // file, and for data files without findings the Privileged Assets checks evaluated in this browser.
    function buildRules() {
        if (savedFindingsState.status === "loaded") {
            rulesSource = "saved";
            rules = SAVED_RULES;
        } else if (DATA_RULES.length) {
            rulesSource = "data";
            rules = DATA_RULES.map(function (rule) {
                var affected = objects.filter(function (object) { return ((FINDINGS_BY_OBJECT || {})[object.objectId] || []).indexOf(rule.key) >= 0; });
                return Object.assign({}, rule, { results: affected.map(objectResult) });
            });
        } else if (objects.length && PA_RULES.length) {
            rulesSource = "browser";
            rules = PA_RULES.map(function (rule) {
                var affected = objects.filter(function (object) { return object._findings.indexOf(rule.key) >= 0; });
                // The objects in the scope of the rule (js/findings.js applies), else all objects of the inventory.
                var scope = typeof FINDING_RULES.applies === "function" ? objects.filter(function (object) { return FINDING_RULES.applies(rule.key, object, findingEnv()); }).length : objects.length;
                return Object.assign({}, rule, { status: affected.length ? "Failed" : "Passed", evaluatedCount: scope, failedCount: affected.length, results: affected.map(objectResult) });
            });
        } else {
            rulesSource = "none";
            rules = [];
        }
        ruleById = Object.create(null);
        rules.forEach(function (rule) {
            rule.objectCount = distinctObjectCount(rule.results);
            rule.search = [rule.id, rule.maesterTestId, rule.title, rule.checkTitle, rule.key].concat(rule.results.map(function (result) {
                return result.displayName || (objectsById[result.objectId] || {}).displayName;
            })).join(" ").toLowerCase();
            ruleById[rule.id] = rule;
        });
    }

    function ruleMatches(rule, skip) {
        if (ruleFilters.search && rule.search.indexOf(ruleFilters.search) < 0) return false;
        if (skip !== "status" && ruleFilters.status && rule.status !== ruleFilters.status) return false;
        if (skip !== "severity" && ruleFilters.severity && rule.severity !== ruleFilters.severity) return false;
        if (skip !== "category" && ruleFilters.category && rule.category !== ruleFilters.category) return false;
        return true;
    }

    function statusBadge(status) {
        return '<span class="pai-status pai-status-' + status.toLowerCase() + '"><span aria-hidden="true">' + STATUS_ICON[status] + "</span>" + esc(status) + "</span>";
    }

    // The exception that accepted a result at the last evaluation has expired by today (UTC): the next evaluation
    // reports the finding again, so the report doesn't present it as accepted.
    function acceptanceExpired(result) {
        var expires = result.exception ? String(result.exception.ExpiresOn || "").slice(0, 10) : "";
        return isIsoDate(expires) && expires < isoToday();
    }

    function acceptedNow(result) { return !!result.exception && !acceptanceExpired(result); }

    function expiredAcceptedResults(rule) { return rule.acceptedResults.filter(acceptanceExpired); }

    // The findings of a check that can get an exception: the open ones and the ones whose exception expired.
    function openResults(rule) { return rule.results.concat(expiredAcceptedResults(rule)); }

    // Accepted findings of a check as of today: without the ones whose exception expired since the evaluation.
    function ruleAcceptance(rule) {
        var expired = expiredAcceptedResults(rule);
        var accepted = Math.max(0, rule.acceptedCount - expired.length);
        var dismissed = Math.max(0, rule.dismissedCount - expired.filter(function (result) { return result.exception.State === "Dismissed"; }).length);
        return { accepted: accepted, dismissed: Math.min(dismissed, accepted), risks: Math.max(0, accepted - dismissed), expired: expired.length };
    }

    // The saved status of a check is not recomputed in the browser: with expired exceptions it is marked as outdated.
    function ruleStaleNote(rule) {
        var expired = expiredAcceptedResults(rule);
        if (!expired.length) return "";
        var dates = Array.from(new Set(expired.map(function (result) { return String(result.exception.ExpiresOn).slice(0, 10); }))).sort();
        return expired.length + (expired.length === 1 ? " exception" : " exceptions") + " expired (" + dates.slice(0, 3).join(", ") + (dates.length > 3 ? ", …" : "") + ") since the last evaluation: " +
            (expired.length === 1 ? "its finding is" : "their findings are") + " open again. The status \"" + rule.status + "\" and the counts are from the last evaluation - run New-EntraOpsReportingData to regenerate the report data.";
    }

    // A check that passes only because risks are accepted: the control isn't met (the Maester Pack skips its test).
    // With an expired exception, the saved status is outdated.
    function riskAcceptedChip(rule) {
        var acceptance = ruleAcceptance(rule);
        return (rule.status === "Passed" && acceptance.risks ?
            ' <span class="chip pai-exception-state pai-exception-riskaccepted pai-rule-risk-chip" title="No open finding, but ' + esc(acceptance.risks) + ' risk-accepted finding(s): the control is not met. The EntraOps Maester Pack skips this test with the accepted risks.">Risk accepted</span>' : "") +
            (acceptance.expired ? ' <span class="chip warn pai-exception-state pai-rule-expired-chip" title="' + esc(ruleStaleNote(rule)) + '">Exception expired</span>' : "");
    }

    // Why a check has no result: the reason of the evaluation, else the default text of its status.
    function ruleReason(rule) {
        if (rule.status === "Failed" || rule.status === "Passed") return "";
        return rule.reason || { Error: "The evaluation of this check failed.", Excluded: "Excluded in EntraOpsConfig.json.", Skipped: rule.reasonCode === "NotApplicable" ? "Nothing in scope." : "Nothing to evaluate." }[rule.status];
    }

    // The label of the reason: "Not applicable" (nothing in scope) and "Data missing" are told apart from other skipped checks.
    function ruleReasonLabel(rule) {
        if (rule.status === "Skipped") return { NotApplicable: "Not applicable", MissingData: "Data missing" }[rule.reasonCode] || "Not evaluated";
        return { Error: "Evaluation error", Excluded: "Excluded" }[rule.status] || "";
    }

    // A note of an evaluated check (for example unresolved groups or a hint for a setting), shown with its results.
    function ruleNote(rule) {
        return (rule.status === "Failed" || rule.status === "Passed") && rule.reason ? rule.reason : "";
    }

    // Without any check result, one card with the command to run replaces the tiles, filters and list.
    function renderRuleStats() {
        var empty = !rules.length;
        $("paiRuleStats").hidden = empty;
        $("secPaiRules").hidden = empty;
        $("paiRuleEmpty").hidden = !empty;
        if (empty) {
            $("paiRuleEmptyNote").innerHTML = savedFindingsState.status === "otherTenant" ? "The saved results belong to tenant " + esc(SAVED_FINDINGS.TenantId) + ", not to this inventory." : "";
            return;
        }
        var counts = {}, failedBySeverity = {};
        rules.forEach(function (rule) {
            counts[rule.status] = (counts[rule.status] || 0) + 1;
            if (rule.status === "Failed") failedBySeverity[rule.severity] = (failedBySeverity[rule.severity] || 0) + 1;
        });
        var tiles = [
            { key: "", label: "Checks", value: rules.length, sub: categoryGroups(rules, function (rule) { return rule; }).length + " categories", title: "EntraOps checks of the saved evaluation" },
            {
                key: "Failed", label: "Failed", value: counts.Failed || 0, cls: "pai-stat-failed", title: "Checks with open findings, by the severity of the check (not the number of affected objects)",
                sub: SEVERITIES.filter(function (severity) { return failedBySeverity[severity]; }).map(function (severity, index, list) {
                    return failedBySeverity[severity] + " " + severity.toLowerCase() + (index === list.length - 1 ? (counts.Failed === 1 ? " check" : " checks") : "");
                }).join(" · ") || "No failed checks"
            },
            { key: "Error", label: "Error", value: counts.Error || 0, sub: "The evaluation failed", cls: "pai-stat-error" },
            { key: "Passed", label: "Passed", value: counts.Passed || 0, sub: "Evaluated without affected objects", cls: "pai-stat-passed" },
            { key: "Skipped", label: "Skipped", value: counts.Skipped || 0, sub: "Data missing or nothing to evaluate", cls: "pai-stat-neutral" },
            { key: "Excluded", label: "Excluded", value: counts.Excluded || 0, sub: "Excluded in EntraOpsConfig.json or deprecated", cls: "pai-stat-neutral" }
        ].filter(function (tile) { return tile.key !== "Error" && tile.key !== "Excluded" || tile.value; });
        if (exceptionsEnabled && Object.keys(exceptions).concat(Object.keys(fileExceptions)).length) {
            var keys = exceptionKeys();
            var count = function (test) { return keys.filter(test).length; };
            // By the status of the file (a local change aside): active ones expiring within 30 days are part of "active".
            var fileStatus = function (key) { var entry = exceptions[key] || fileExceptions[key]; return !fileExceptions[key] ? "" : exceptionExpired(entry) ? "Expired" : fileExceptions[key].status || "Active"; };
            var active = count(function (key) { return exceptions[key] && !exceptionExpired(exceptions[key]) && fileStatus(key) !== "Stale" && fileStatus(key) !== "Expired"; });
            var expiring = count(function (key) { return exceptions[key] && exceptionExpiring(exceptions[key]) && fileStatus(key) !== "Stale"; });
            var expired = count(function (key) { return exceptions[key] && exceptionExpired(exceptions[key]); });
            var stale = count(function (key) { return exceptions[key] && fileStatus(key) === "Stale"; });
            var pending = count(exceptionChange);
            tiles.push({
                key: "__exceptions", label: "Exceptions", value: Object.keys(exceptions).length, cls: "pai-stat-neutral", title: "Dismissed and risk-accepted findings of the Finding Exceptions File, with the changes of this browser",
                sub: [active + " active" + (expiring ? " (" + expiring + " expiring soon)" : ""), expired ? expired + " expired" : "", stale ? stale + " without finding" : "", pending ? pending + " pending" : ""].filter(Boolean).join(" · ")
            });
        }
        statTilesHtml($("paiRuleStats"), tiles, "data-rule-stat");
        $("paiRuleBar").innerHTML = STATUS_ORDER.filter(function (status) { return counts[status]; }).map(function (status) {
            return '<span class="pai-bar-' + status.toLowerCase() + '" style="flex-grow:' + counts[status] + '" title="' + esc(counts[status] + " " + status.toLowerCase()) + '"></span>';
        }).join("");
    }

    function renderRuleSource() {
        var note = $("paiRuleSource"), text = "";
        if (rulesSource === "saved") {
            var saved = new Date(SAVED_FINDINGS.GeneratedAt);
            text = "Results of " + (isNaN(saved) ? esc(SAVED_FINDINGS.GeneratedAt) : esc(saved.toLocaleString())) + " · EntraOps " + esc((SAVED_FINDINGS.Generator || {}).Version || "") +
                (SAVED_FINDINGS.TenantName ? " · " + esc(SAVED_FINDINGS.TenantName) : "") + ". The Overview re-evaluates the Privileged Assets checks with What-if; this view shows the saved evaluation.";
        } else if (rules.length) {
            text = (savedFindingsState.status === "otherTenant" ? "The saved results belong to tenant " + esc(SAVED_FINDINGS.TenantId) + "." : "The saved results of all EntraOps checks are not loaded.") +
                " Only the Privileged Assets checks of the inventory are shown" + (rulesSource === "browser" ? ", evaluated in this browser because the data file has no findings" : "") +
                ": <code>New-EntraOpsReportingData</code> saves the results of all checks (<code>Reports/Findings/data/findings.js</code>).";
        }
        note.hidden = !text;
        note.innerHTML = text ? "<p>" + text + "</p>" : "";
    }

    // Data gaps of the saved evaluation (DataGaps of findings.json, EntraOps 1.2.0 or later): data that was missing, so
    // the checks named with a gap evaluate less than their status suggests. Files without DataGaps show no box. The
    // messages name objects of the tenant, so the box is built with textContent, never as HTML.
    function renderDataGaps() {
        var box = $("paiDataGaps");
        if (!box) return;
        var saved = rulesSource === "saved" && SAVED_FINDINGS && Array.isArray(SAVED_FINDINGS.DataGaps) ? SAVED_FINDINGS.DataGaps : [];
        var gaps = saved.filter(function (gap) { return gap && typeof gap === "object" && (gap.Message || gap.Code); });
        box.textContent = "";
        box.hidden = !gaps.length;
        if (!gaps.length) return;
        var title = document.createElement("div");
        title.className = "callout-title";
        title.textContent = "Data gaps";
        var intro = document.createElement("p");
        intro.className = "pai-small";
        intro.textContent = "Data was missing in the evaluation, so the affected checks evaluate less than their status suggests:";
        var list = document.createElement("ul");
        list.className = "pai-data-gap-list";
        gaps.forEach(function (gap) {
            var item = document.createElement("li");
            item.setAttribute("data-gap", String(gap.Code || ""));
            var message = document.createElement("div");
            message.className = "pai-data-gap-message";
            message.textContent = String(gap.Message || gap.Code);
            item.appendChild(message);
            var ruleIds = (Array.isArray(gap.RuleIds) ? gap.RuleIds : []).map(String).filter(Boolean);
            if (ruleIds.length) {
                var checks = document.createElement("div");
                checks.className = "muted pai-small pai-data-gap-rules";
                checks.appendChild(document.createTextNode(ruleIds.length === 1 ? "Affected check: " : "Affected checks: "));
                ruleIds.forEach(function (ruleId, index) {
                    if (index) checks.appendChild(document.createTextNode(", "));
                    var rule = findRule(ruleId);
                    if (!rule) { checks.appendChild(document.createTextNode(ruleId)); return; }
                    var button = document.createElement("button");
                    button.type = "button";
                    button.className = "pai-link pai-small";
                    button.setAttribute("data-rule-open", rule.id);
                    button.title = rule.title;
                    button.textContent = rule.id;
                    checks.appendChild(button);
                });
                item.appendChild(checks);
            }
            list.appendChild(item);
        });
        box.appendChild(title);
        box.appendChild(intro);
        box.appendChild(list);
    }

    function ruleAffected(rule) {
        var unclassified = rule.unclassifiedCount ? ' <span class="muted pai-small pai-rule-unclassified-hint" title="Affected unclassified objects, not listed by default">+' + esc(unclassifiedObjectCount(rule)) + " unclassified</span>" : "";
        var acceptance = ruleAcceptance(rule);
        var risks = acceptance.risks;
        var accepted = (risks ? ' <span class="muted pai-small pai-rule-accepted-hint" title="Findings risk accepted in the Finding Exceptions File, not counted">+' + esc(risks) + " risk accepted</span>" : "") +
            (acceptance.dismissed ? ' <span class="muted pai-small pai-rule-accepted-hint" title="Findings dismissed as false positives in the Finding Exceptions File, not counted">+' + esc(acceptance.dismissed) + " dismissed</span>" : "") +
            // Not accepted any more, and not in the saved count of open findings either.
            (acceptance.expired ? ' <span class="pai-small pai-rule-expired-hint" title="' + esc(ruleStaleNote(rule)) + '">+' + esc(acceptance.expired) + " exception expired</span>" : "");
        // Objects first; the results (for example one per role assignment) and the evaluated instances below.
        var of = rule.evaluatedCount ? "of " + rule.evaluatedCount + " evaluated" : "";
        if (rule.status === "Failed") {
            var objectCount = rule.objectCount || rule.failedCount;
            var results = rule.failedCount !== objectCount ? rule.failedCount + " results" + (of ? " · " + of : "") : of;
            return "<b>" + esc(objectCount) + "</b> " + (objectCount === 1 ? "object" : "objects") + (results ? '<div class="muted pai-small pai-rc-results">' + esc(results) + "</div>" : "") + accepted + unclassified;
        }
        if (rule.status === "Passed") return "0 objects" + (of ? '<div class="muted pai-small pai-rc-results">' + esc(of) + "</div>" : "") + accepted;
        return '<span class="muted" aria-label="Not evaluated">–</span>' + unclassified;
    }

    // The object of a result (its group in the panel of a check): its object, else its instance.
    function resultObjectKey(result) { return result.objectId || result.instanceId || result.displayName || ""; }

    function distinctObjectCount(results) {
        var ids = Object.create(null);
        results.forEach(function (result) { ids[resultObjectKey(result)] = true; });
        return Object.keys(ids).length;
    }

    // Distinct objects of the unclassified results (a result is one instance, for example one assignment path).
    function unclassifiedObjectCount(rule) {
        return distinctObjectCount(rule.unclassifiedResults) || rule.unclassifiedCount;
    }

    function renderRules() {
        if (!rules.length) return;
        var statusCounts = {}, severityCounts = {}, categoryCounts = {}, statusTotal = 0, severityTotal = 0, categoryTotal = 0;
        rules.forEach(function (rule) {
            if (ruleMatches(rule, "status")) { statusTotal++; statusCounts[rule.status] = (statusCounts[rule.status] || 0) + 1; }
            if (ruleMatches(rule, "severity")) { severityTotal++; severityCounts[rule.severity] = (severityCounts[rule.severity] || 0) + 1; }
            if (ruleMatches(rule, "category")) { categoryTotal++; categoryCounts[rule.category] = (categoryCounts[rule.category] || 0) + 1; }
        });
        var pill = function (facet, value, label, count, prefix) { return EntraOpsFilters.pill(ruleFilters, facet, value, label, count, { prefix: prefix }); };
        $("paiRuleStatusPills").innerHTML = pill("status", "", "All", statusTotal) + STATUS_ORDER.filter(function (status) {
            return (status !== "Excluded" && status !== "Error") || statusCounts[status] || ruleFilters.status === status;
        }).map(function (status) {
            return pill("status", status, status, statusCounts[status] || 0, '<span class="pai-status-dot pai-status-' + status.toLowerCase() + '" aria-hidden="true"></span>');
        }).join("");
        $("paiRuleSeverityPills").innerHTML = pill("severity", "", "All", severityTotal) + SEVERITIES.map(function (severity) {
            return pill("severity", severity, severity, severityCounts[severity] || 0, '<span class="pai-sev-dot ' + severityClass(severity) + '" aria-hidden="true"></span>');
        }).join("");
        $("paiRuleCategoryPills").innerHTML = pill("category", "", "All", categoryTotal) + categoryGroups(rules, function (rule) { return rule; }).map(function (group) {
            return pill("category", group.key, group.title, categoryCounts[group.key] || 0);
        }).join("");

        var visible = rules.filter(function (rule) { return ruleMatches(rule); });
        $("paiRuleCount").textContent = visible.length + " of " + rules.length + " checks";
        var groups = categoryGroups(visible, function (rule) { return rule; });
        visibleCategories = groups.map(function (group) { return group.key; });
        $("paiRuleCollapseAll").textContent = ruleGroups.allCollapsed(visibleCategories) ? "Expand all" : "Collapse all";
        $("paiRuleCollapseAll").disabled = !groups.length;
        $("paiRuleList").innerHTML = groups.map(function (group) {
            var list = group.entries.sort(function (a, b) {
                return STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.id.localeCompare(b.id);
            });
            var summary = STATUS_ORDER.map(function (status) {
                var count = list.filter(function (rule) { return rule.status === status; }).length;
                return count ? '<span class="pai-rule-count"><span class="pai-status-dot pai-status-' + status.toLowerCase() + '"></span>' + count + " " + status.toLowerCase() + "</span>" : "";
            }).join("");
            return ruleGroups.open(group.key) + ruleGroups.head(group.key, group.title, summary) + ruleGroups.body(group.key, '<div class="table-wrap"><table class="grid-table pai-rule-table"><thead><tr><th class="no-sort pai-rcol-status">Status</th><th class="no-sort">Check</th><th class="no-sort pai-rcol-sev">Severity</th><th class="no-sort pai-rcol-affected">Affected objects</th><th class="no-sort pai-rcol-source">Source</th></tr></thead><tbody>' +
                list.map(function (rule) {
                    // The status names Error and Excluded; skipped checks tell "Not applicable" and "Data missing" apart.
                    var reasonPrefix = rule.status === "Skipped" && (rule.reasonCode === "NotApplicable" || rule.reasonCode === "MissingData") ? ruleReasonLabel(rule) + ": " : "";
                    var reason = ruleReason(rule) ? reasonPrefix + ruleReason(rule) : ruleNote(rule) ? "Note: " + ruleNote(rule) : "";
                    return '<tr class="pai-rule-row" data-rule="' + esc(rule.id) + '"><td class="pai-rc-status">' + statusBadge(rule.status) + riskAcceptedChip(rule) + "</td>" +
                        '<td class="pai-rc-check"><button type="button" class="pai-link" data-rule-open="' + esc(rule.id) + '">' + esc(rule.checkTitle) + '</button><div class="muted pai-small">' +
                        esc([rule.id, rule.title].filter(Boolean).join(" · ")) + "</div>" + (reason ? '<div class="muted pai-small pai-rule-why">' + esc(reason) + "</div>" : "") +
                        (ruleStaleNote(rule) ? '<div class="pai-small pai-rule-stale">' + esc(ruleStaleNote(rule)) + "</div>" : "") + "</td>" +
                        '<td class="pai-rc-sev"><span class="pai-sev ' + severityClass(rule.severity) + '">' + esc(rule.severity) + "</span></td>" +
                        '<td class="pai-rc-affected"><span class="pai-rc-label">Affected objects: </span>' + ruleAffected(rule) + "</td>" +
                        '<td class="pai-rc-source pai-small">' + esc((AREA_INFO[rule.area] || { label: rule.area }).label) + "</td></tr>";
                }).join("") + "</tbody></table></div>") + "</div>";
        }).join("") || '<p class="muted">No checks match the current filters.</p>';
    }

    // "18 role assignments" or "3 findings": what the results of a check are.
    function resultNoun(results) {
        var count = results.length;
        var assignments = count > 0 && results.every(function (result) { return result.evidence && (result.evidence.Role || result.evidence.RoleDefinitionName); });
        return count + " " + (assignments ? "role assignment" : "finding") + (count === 1 ? "" : "s");
    }

    // The tier of the object of a result: the inventory object, else the tier name or level of the result.
    function resultTierHtml(result, object) {
        if (result.unclassified) return tierBadge("Unclassified");
        if (object) return tierBadge(effectiveTier(object));
        if (result.adminTierLevelName && Object.prototype.hasOwnProperty.call(TIER_LABEL, result.adminTierLevelName)) return tierBadge(result.adminTierLevelName);
        return LEVEL_TIER[result.adminTierLevel] ? tierBadge(LEVEL_TIER[result.adminTierLevel]) : '<span class="muted">-</span>';
    }

    function resultObjectCell(result) {
        var object = objectsById[result.objectId];
        var name = object ? '<button type="button" class="pai-link" data-open="' + esc(object.objectId) + '">' + esc(object.displayName) + "</button>" : esc(result.displayName || result.objectId || "-");
        var type = typeLabel(object ? object.objectType : result.objectType);
        // The tier sits under the name and type: a column of its own was too narrow for "Management Plane".
        return name + (type ? '<div class="muted pai-small">' + esc(type) + "</div>" : "") + (object || !result.objectId ? "" : '<div class="muted pai-small cell-mono">' + esc(result.objectId) + "</div>") +
            '<div class="pai-rres-tier">' + resultTierHtml(result, object) + "</div>";
    }

    // A result can get an exception in the panel: an open finding without an exception of this browser that applies.
    function resultSelectable(rule, result) {
        if (!exceptionsEnabled || result.unclassified || acceptedNow(result)) return false;
        var match = exceptionForResult(rule, result);
        return !match || (!exceptionChange(match.key) && exceptionExpired(match.entry));
    }

    function resultRow(rule, result, child) {
        var columns = exceptionsEnabled ? 3 : 2;
        var rowClass = [result.unclassified ? "pai-rule-unclassified-row" : acceptedNow(result) ? "pai-rule-accepted-row" : result.exception ? "pai-rule-expired-row" : "", child ? "pai-rres-child" : ""].filter(Boolean).join(" ");
        var accept = exceptionsEnabled && !result.unclassified && !acceptedNow(result) && ruleBlade.acceptFor === resultId(result);
        return "<tr" + (rowClass ? ' class="' + rowClass + '"' : "") + ' data-result="' + esc(resultId(result)) + '"><td class="pai-rres-object">' + (child ? "" : resultObjectCell(result)) + "</td>" +
            '<td class="pai-small pai-rres-details">' + esc(result.message) + findingLinksHtml(rule, result) + evidenceHtml(result.evidence) + "</td>" +
            (exceptionsEnabled ? '<td class="pai-rres-exception">' + resultExceptionCell(rule, result) + "</td>" : "") + "</tr>" +
            (accept ? '<tr class="pai-accept-row"><td colspan="' + columns + '">' + acceptFormHtml({ result: result }) + "</td></tr>" : "");
    }

    // An object with several results: one row with the number of results (and the first message), expandable.
    function resultGroupRows(rule, group, expanded) {
        var first = group.results[0];
        var selectable = group.results.filter(function (result) { return resultSelectable(rule, result); });
        var selected = selectable.filter(function (result) { return ruleBlade.selected[resultId(result)]; }).length;
        var pending = group.results.filter(function (result) { var match = !acceptedNow(result) && exceptionForResult(rule, result); return match && exceptionChange(match.key); }).length;
        var kind = first.unclassified ? " pai-rule-unclassified-row" : acceptedNow(first) ? " pai-rule-accepted-row" : first.exception ? " pai-rule-expired-row" : "";
        var exception = "";
        if (exceptionsEnabled) {
            exception = acceptedNow(first) ? exceptionStateChip({ State: first.exception.State || "" }) + '<div class="muted pai-small">' + esc(group.results.length) + " accepted</div>" :
                (first.exception ? '<span class="chip warn pai-exception-state pai-exception-expired">Exception expired</span>' : "") +
                (pending ? '<div class="muted pai-small">' + esc(pending) + " pending</div>" : "") +
                (selectable.length ? '<label class="pai-check pai-rres-select"><input type="checkbox" data-select-group="' + esc(group.key) + '"' + (selected === selectable.length ? " checked" : "") +
                    (selected && selected < selectable.length ? ' data-indeterminate="true"' : "") + ' aria-label="Select the findings of this object" /> Select all</label>' : "");
        }
        return '<tr class="pai-rgroup' + kind + '" data-result-group="' + esc(group.key) + '"><td class="pai-rres-object">' + resultObjectCell(first) + "</td>" +
            '<td class="pai-small pai-rres-details"><button type="button" class="pai-rgroup-toggle" data-result-group-toggle="' + esc(group.key) + '" aria-expanded="' + (expanded ? "true" : "false") + '">' +
            '<span class="pai-rgroup-chevron" aria-hidden="true"></span>' + esc(resultNoun(group.results)) + "</button>" +
            (expanded ? "" : '<div class="muted pai-rgroup-preview">' + esc(first.message) + "</div>") + "</td>" +
            (exceptionsEnabled ? '<td class="pai-rres-exception">' + exception + "</td>" : "") + "</tr>" +
            (expanded ? group.results.map(function (result) { return resultRow(rule, result, true); }).join("") : "");
    }

    // The results of the check grouped by object, in the order of the results: open findings, then the accepted
    // and the unclassified ones when they are shown.
    function ruleResultGroups(rule) {
        var term = ruleBlade.search;
        // Findings whose exception expired are always listed (after the open ones): they are open again.
        var all = rule.results.concat(expiredAcceptedResults(rule), ruleBlade.showAccepted ? rule.acceptedResults.filter(acceptedNow) : [], ruleBlade.showUnclassified ? rule.unclassifiedResults : []);
        var results = all.filter(function (result) {
            return !term || [result.displayName, (objectsById[result.objectId] || {}).displayName, result.objectId, result.message].join(" ").toLowerCase().indexOf(term) >= 0;
        });
        // Without prototype: the key of an open result is its object or instance ID as it is.
        var groups = [], byKey = Object.create(null);
        results.forEach(function (result) {
            var key = (result.unclassified ? "u|" : acceptedNow(result) ? "a|" : result.exception ? "x|" : "") + resultObjectKey(result);
            if (!byKey[key]) groups.push(byKey[key] = { key: key, results: [] });
            byKey[key].results.push(result);
        });
        return { groups: groups, results: results };
    }

    function ruleResultRows(rule) {
        var found = ruleResultGroups(rule);
        var shown = ruleBlade.showAll ? found.groups : found.groups.slice(0, MAX_RULE_GROUPS);
        // A search shows the matching results of an object without expanding it.
        var rows = shown.map(function (group) {
            return group.results.length === 1 ? resultRow(rule, group.results[0], false) : resultGroupRows(rule, group, Boolean(ruleBlade.search) || ruleBlade.expanded[group.key] === true);
        }).join("");
        var empty = ruleBlade.search ? "No affected objects match the search." : rule.unclassifiedCount && !ruleBlade.showUnclassified ? "No classified objects are affected." :
            ruleAcceptance(rule).accepted && !ruleBlade.showAccepted ? "No affected objects apart from the accepted findings." : "No affected objects.";
        return { html: rows || '<tr><td colspan="' + (exceptionsEnabled ? 3 : 2) + '" class="muted">' + empty + "</td></tr>", groups: found.groups.length, results: found.results.length, hidden: found.groups.length - shown.length };
    }

    // "46 objects · 105 results", or "15" when every object has one result.
    function objectResultText(objectCount, resultCount) {
        return objectCount === resultCount ? String(objectCount) : objectCount + (objectCount === 1 ? " object · " : " objects · ") + resultCount + " results";
    }

    function renderRuleResults() {
        var rule = ruleById[ruleBlade.ruleId];
        if (!rule || !$("paiRuleResultsBody")) return;
        var rows = ruleResultRows(rule);
        $("paiRuleResultsBody").innerHTML = rows.html;
        $("paiRuleResultsBody").querySelectorAll("[data-indeterminate]").forEach(function (box) { box.indeterminate = true; });
        $("paiRuleResultsMore").innerHTML = rows.hidden ? '<button type="button" class="btn small" data-rule-all>Show all ' + objectResultText(rows.groups, rows.results).replace(/^(\d+)$/, "$1 affected objects") + "</button>" : "";
        var unclassifiedObjects = unclassifiedObjectCount(rule);
        var expiredCount = expiredAcceptedResults(rule).length;
        $("paiRuleResultsTitle").textContent = "Affected objects (" + objectResultText(rule.objectCount, rule.results.length) +
            (expiredCount ? " + " + expiredCount + " with an expired exception" : "") +
            (ruleBlade.showAccepted ? " + " + (rule.acceptedResults.length - expiredCount) + " accepted" : "") +
            (ruleBlade.showUnclassified ? " + " + unclassifiedObjects + " unclassified object" + (unclassifiedObjects === 1 ? "" : "s") +
                (rule.unclassifiedResults.length !== unclassifiedObjects ? " with " + rule.unclassifiedResults.length + " results" : "") : "") + ")";
        renderBulkBar(rule);
    }

    // Bulk exceptions: the selected results of the panel get one exception each (or one per object), with one form.
    function selectedResults(rule) {
        return openResults(rule).filter(function (result) { return ruleBlade.selected[resultId(result)] && resultSelectable(rule, result); });
    }

    function renderBulkBar(rule) {
        var bar = $("paiRuleBulkBar");
        if (!bar) return;
        var selectable = openResults(rule).filter(function (result) { return resultSelectable(rule, result); });
        bar.hidden = !exceptionsEnabled || selectable.length < 2;
        if (bar.hidden) { $("paiRuleBulkForm").innerHTML = ""; return; }
        var selected = selectedResults(rule);
        var objectsSelected = distinctObjectCount(selected);
        bar.innerHTML = '<span class="muted pai-small" id="paiRuleBulkCount">' + (selected.length ? esc(selected.length) + " selected (" + esc(objectsSelected) + (objectsSelected === 1 ? " object)" : " objects)") : "Select findings to accept them together") + "</span>" +
            '<button type="button" class="btn small" data-bulk-select-all>Select all shown</button>' +
            '<button type="button" class="btn small primary" data-bulk-accept' + (selected.length ? "" : " disabled") + ">Accept selected…</button>" +
            (selected.length ? '<button type="button" class="btn small" data-bulk-clear>Clear selection</button>' : "");
        if (!selected.length) ruleBlade.bulkOpen = false;
        var form = $("paiBulkAcceptForm");
        if (!ruleBlade.bulkOpen) { $("paiRuleBulkForm").innerHTML = ""; return; }
        if (!form) {
            $("paiRuleBulkForm").innerHTML = acceptFormHtml({ bulk: selected });
            updateAcceptState($("paiBulkAcceptForm"));
            return;
        }
        // The open form keeps its input when the selection changes: only the numbers change.
        var fresh = document.createElement("div");
        fresh.innerHTML = acceptFormHtml({ bulk: selected });
        [".pai-accept-title", ".pai-accept-scope"].forEach(function (selector) {
            var checked = form.querySelector('input[name="Scope"]:checked');
            form.querySelector(selector).innerHTML = fresh.querySelector(selector).innerHTML;
            if (checked) form.querySelector('input[name="Scope"][value="' + checked.value + '"]').checked = true;
        });
        form.querySelector('button[type="submit"]').textContent = fresh.querySelector('button[type="submit"]').textContent;
    }

    // Info bar of a check with affected unclassified objects: they're counted, and listed only on request.
    function ruleUnclassifiedInfo(rule) {
        if (!rule.unclassifiedCount) return "";
        var objectCount = unclassifiedObjectCount(rule);
        var instances = rule.unclassifiedCount !== objectCount ? " (" + rule.unclassifiedCount + " affected instances)" : "";
        var toggle = rule.unclassifiedResults.length ? '<label class="pai-check pai-rule-unclassified-toggle"><input type="checkbox" id="paiRuleShowUnclassified"' + (ruleBlade.showUnclassified ? " checked" : "") +
            " /> Show unclassified objects in the list</label>" : "";
        var unclassifiedRule = ruleById["EO.2001"] ? '<button type="button" class="pai-link" data-rule-open="EO.2001">EO.2001 Unclassified object</button>' : "EO.2001 Unclassified object";
        return '<div class="callout pai-rule-unclassified" role="status"><b>' + esc(objectCount) + " unclassified object" + (objectCount === 1 ? "" : "s") + "</b>" + esc(instances) +
            (rule.status === "Failed" ? " would also apply to this check. " : " would apply to this check. ") +
            "They are not listed by default: their tier is unknown, so the check can't tell a tier breach from missing classification. " +
            "Classify them (" + unclassifiedRule + ") to evaluate them." + toggle + "</div>";
    }

    function showRuleNotFound(ruleId) {
        $("paiRuleNotFound").hidden = false;
        $("paiRuleNotFound").innerHTML = "Check <code>" + esc(ruleId) + "</code> was not found in the loaded results.";
    }

    // urlMode: "push" or "replace" writes #rule= to the URL, false leaves the URL as it is. Returns false for an unknown check.
    function openRuleBlade(ruleId, urlMode) {
        var rule = findRule(ruleId);
        if (!rule) return false;
        ruleId = rule.id;
        ruleBlade = newRuleBlade(ruleId);
        $("paiRuleNotFound").hidden = true;
        var kv = function (label, value) { return value === "" || value == null ? "" : "<dt>" + esc(label) + "</dt><dd>" + value + "</dd>"; };
        var area = AREA_INFO[rule.area] || { label: rule.area };
        var evaluated = rule.status === "Failed" || rule.status === "Passed";
        $("paiRuleKicker").textContent = "Check · " + rule.categoryTitle;
        $("paiRuleTitle").textContent = rule.checkTitle;
        $("paiRuleChips").innerHTML = statusBadge(rule.status) + riskAcceptedChip(rule) + '<span class="pai-sev ' + severityClass(rule.severity) + '">' + esc(rule.severity) + "</span>" +
            '<span class="pai-rule-id" title="EntraOps check">' + esc(rule.id) + "</span>";
        $("paiRuleBlade").className = "drawer pai-blade " + (rule.status === "Failed" ? severityClass(rule.severity) : "pai-blade-" + rule.status.toLowerCase()) + (panelOpen("paiRuleBlade") ? " open" : "");

        // Objects, results (for example one per role assignment of an object) and the evaluated instances.
        var stats = [["Affected objects", evaluated ? esc(rule.objectCount) : "–"], ["Results", evaluated ? esc(rule.failedCount) : "–"], ["Evaluated", evaluated ? esc(rule.evaluatedCount) : "–"]].map(function (stat) {
            return '<div class="pai-blade-stat"><div class="pai-blade-stat-label">' + esc(stat[0]) + '</div><div class="pai-blade-stat-value">' + stat[1] + "</div></div>";
        }).join("");
        var parameters = Object.keys(rule.parameters).map(function (name) {
            var value = rule.parameters[name];
            return kv(name, esc(Array.isArray(value) ? (value.length ? value.join(", ") : "none") : value));
        }).join("");
        var actions = (area.href ? '<a class="btn small" href="' + esc(area.href({ objectId: "" }).replace(/#asset=$/, "")) + '">Open ' + esc(area.report) + " &#8599;</a>" : "") +
            (rule.maesterTestId ? ' <a class="btn small" href="' + esc(MAESTER_PACK_TESTS + "Test." + rule.maesterTestId + ".md") + '" target="_blank" rel="noopener noreferrer">Maester test ' + esc(rule.maesterTestId) + " &#8599;</a>" : "");
        var reasonLabel = ruleReasonLabel(rule);
        var note = ruleNote(rule);
        var rating = function (label, level, text) {
            return level ? '<div class="pai-rating"><div class="pai-rating-head"><span class="pai-rating-label">' + esc(label) + '</span><span class="pai-level pai-level-' + esc(level.toLowerCase()) + '">' + esc(level) + "</span></div>" +
                (text ? '<div class="muted pai-small">' + esc(text) + "</div>" : "") + "</div>" : "";
        };
        var ratings = rating("Implementation effort", rule.effort, rule.effortDescription) + rating("User impact", rule.userImpact, rule.userImpactDescription);

        $("paiRuleBody").innerHTML = '<div class="pai-blade-stats pai-blade-stats-3">' + stats + "</div>" + (actions ? '<div class="pai-drawer-actions">' + actions + "</div>" : "") +
            (reasonLabel ? '<div class="callout scope pai-rule-reason"><b>' + esc(reasonLabel) + ":</b> " + esc(ruleReason(rule)) +
                (rule.status === "Excluded" && !rule.reason ? " (<code>Findings.ExcludedRules</code> or the excluded risk flags)" : "") + "</div>" : "") +
            (note ? '<div class="callout pai-rule-note" role="note"><b>Note:</b> ' + esc(note) + "</div>" : "") +
            ruleAcceptedInfo(rule) + ruleUnclassifiedInfo(rule) +
            (rule.description ? '<details class="drawer-section" open><summary>Description</summary><div class="pai-md pai-drawer-pad">' + renderMarkdown(rule.description) + "</div></details>" : "") +
            (rule.remediation ? '<details class="drawer-section" open><summary>Remediation action</summary><div class="pai-md pai-drawer-pad">' + renderMarkdown(rule.remediation) + "</div></details>" : "") +
            (ratings ? '<details class="drawer-section" open><summary>Effort and user impact</summary><div class="pai-ratings pai-drawer-pad">' + ratings + "</div></details>" : "") +
            (rule.references && rule.references.length ? '<details class="drawer-section" id="paiRuleReferences" open><summary>Resources (' + rule.references.length + ")</summary>" + referencesHtml(rule) + "</details>" : "") +
            (parameters ? '<details class="drawer-section" open><summary>Settings</summary><dl class="kv">' + parameters + "</dl></details>" : "") +
            (rule.results.length || rule.unclassifiedResults.length || rule.acceptedResults.length ? '<details class="drawer-section" open><summary id="paiRuleResultsTitle">Affected objects (' + rule.results.length + ')</summary><div class="pai-drawer-pad">' +
                '<input type="search" id="paiRuleResultSearch" class="pai-input pai-rule-result-search" placeholder="Search affected objects" autocomplete="off" aria-label="Search affected objects" />' +
                '<div class="pai-toolbar pai-rule-bulk-bar" id="paiRuleBulkBar" hidden></div><div id="paiRuleBulkForm"></div>' +
                '<table class="grid-table pai-drawer-table pai-rule-results"><thead><tr><th class="no-sort pai-rres-object">Object and tier</th><th class="no-sort">Details</th>' + (exceptionsEnabled ? '<th class="no-sort pai-rres-exception">Exception</th>' : "") + '</tr></thead><tbody id="paiRuleResultsBody"></tbody></table>' +
                '<div id="paiRuleResultsMore" class="pai-rule-more"></div></div></details>' : "");
        renderRuleResults();
        $("paiRuleBody").scrollTop = 0;
        showPanel("paiRuleBlade", "paiRuleBackdrop");
        setUrl(location.pathname + "?view=findings#rule=" + encodeURIComponent(ruleId), urlMode);
        return true;
    }

    function closeRuleBlade(updateUrl) {
        if (!hidePanel("paiRuleBlade", "paiRuleBackdrop")) return;
        if (updateUrl !== false && /^#rule=/.test(location.hash || "")) setUrl(location.pathname + location.search, "replace");
    }

    // ---- Finding exceptions: dismissed and risk-accepted findings ---------------------------------------------
    // The Finding Exceptions File (Findings.ExceptionsFilePath) as the saved results report it, with the changes of
    // this browser on top (like the worklist). Exported, it is saved in the EntraOps folder (committed, or kept in a
    // local folder), and the next evaluation applies it: changes in this browser don't change the results.
    // v2 keeps the pending changes per tenant (key + "." + tenant); v1 had one key for all tenants.
    var EXCEPTION_STORE_KEY = "entraops.privilegedAssets.findingExceptions.v2";
    var LEGACY_EXCEPTION_STORE_KEY = "entraops.privilegedAssets.findingExceptions.v1";
    var EXCEPTION_BY_KEY = "entraops.privilegedAssets.findingExceptions.acceptedBy";
    var EXCEPTION_SETTINGS = (SAVED_FINDINGS && SAVED_FINDINGS.ExceptionSettings) || {};
    var EXCEPTION_FILE = String(EXCEPTION_SETTINGS.FilePath || "./Classification/FindingExceptions.json");
    var EXCEPTION_MAX_DAYS = EXCEPTION_SETTINGS.MaxDays == null ? 180 : Math.max(0, Number(EXCEPTION_SETTINGS.MaxDays) || 0);
    var EXCEPTION_FIELDS = ["RuleId", "InstanceId", "ObjectId", "DisplayName", "State", "Justification", "AcceptedBy", "AcceptedOn", "ExpiresOn", "Reference"];
    var EXCEPTION_STATE_LABEL = { RiskAccepted: "Risk accepted", Dismissed: "Dismissed" };
    var EXCEPTION_STATUS = {
        Active: { label: "Active", cls: "unchanged", title: "Accepts findings of the last evaluation." },
        Expired: { label: "Expired", cls: "removed", title: "Expired: its findings are reported again. Renew or remove it." },
        Stale: { label: "No finding", cls: "modified", title: "No finding of the last evaluation matches (fixed or changed). Remove it." },
        NotEvaluated: { label: "Not evaluated", cls: "unchanged", title: "The check was not evaluated." },
        Added: { label: "Added", cls: "added", title: "Added in this browser: export the file to apply it." },
        Changed: { label: "Changed", cls: "modified", title: "Changed in this browser: export the file to apply it." },
        Removed: { label: "Removed", cls: "removed", title: "Removed in this browser: export the file to apply it." }
    };
    var EXPIRING_DAYS = 30;
    var exceptionsEnabled = false;
    var fileExceptions = {};
    var exceptions = {};
    // The file changed since the local changes of this browser were made (fingerprint of the file at that time).
    var exceptionFileChanged = false;
    // The stored changes of that case ({ baseFingerprint, upserts, removals }): not applied until they are kept.
    var heldExceptionChanges = null;
    // Lengths of the form fields: longer values of a file are kept, but can't be edited in the form.
    var EXCEPTION_FIELD_MAX = { Justification: 1000 };

    // Today as UTC calendar date, like the evaluation in PowerShell ((Get-Date).ToUniversalTime().Date): the browser
    // and the evaluation agree on AcceptedOn and on the day an exception expires, in every time zone.
    function isoToday() {
        return new Date().toISOString().slice(0, 10);
    }

    // A real calendar date as yyyy-MM-dd (2026-13-45 and 2026-02-30 are not).
    function isIsoDate(value) {
        var match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ""));
        if (!match) return false;
        var date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
        return date.getUTCFullYear() === Number(match[1]) && date.getUTCMonth() === Number(match[2]) - 1 && date.getUTCDate() === Number(match[3]);
    }

    function isoAddDays(iso, days) {
        var date = new Date(iso + "T00:00:00Z");
        date.setUTCDate(date.getUTCDate() + days);
        return date.toISOString().slice(0, 10);
    }

    // Key of an exception like Get-EntraOpsFindingExceptionKey: rule, instance and (without instance) object.
    function exceptionKey(entry) {
        return [entry.RuleId, entry.InstanceId, entry.InstanceId ? "" : entry.ObjectId].join("|").toLowerCase();
    }

    // An exception of the file or of an import, checked like Read-EntraOpsFindingExceptionFile.
    function sanitizeException(raw) {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, reason: "not an object" };
        var get = function (name) {
            var match = Object.keys(raw).filter(function (key) { return key.toLowerCase() === name.toLowerCase(); })[0];
            return match && raw[match] != null ? String(raw[match]).trim() : "";
        };
        var fail = function (reason) { return { ok: false, reason: reason }; };
        // Values are kept as they are (Read-EntraOpsFindingExceptionFile doesn't shorten them either).
        var value = {};
        EXCEPTION_FIELDS.forEach(function (name) { value[name] = get(name); });
        value.RuleId = value.RuleId.toUpperCase();
        value.State = Object.keys(EXCEPTION_STATE_LABEL).filter(function (state) { return state.toLowerCase() === value.State.toLowerCase(); })[0] || "";
        if (!/^EO\.\d{4}$/.test(value.RuleId)) return fail("RuleId must be a check ID like EO.1001");
        if (!value.InstanceId && !value.ObjectId) return fail("InstanceId or ObjectId is required");
        if (!value.State) return fail("State must be RiskAccepted or Dismissed");
        if (!value.Justification) return fail("Justification is required");
        var dateError = ["AcceptedOn", "ExpiresOn"].filter(function (name) {
            var match = /^\d{4}-\d{2}-\d{2}/.exec(value[name]);
            value[name] = match ? match[0] : value[name];
            return value[name] && !(match && isIsoDate(match[0]));
        })[0];
        if (dateError) return fail(dateError + " must be a date (yyyy-mm-dd)");
        if (value.State === "RiskAccepted" && (!value.AcceptedOn || !value.ExpiresOn)) return fail("a risk-accepted exception needs AcceptedOn and ExpiresOn");
        return { ok: true, value: value };
    }

    function sameException(left, right) {
        return EXCEPTION_FIELDS.every(function (name) { return (left[name] || "") === (right[name] || ""); });
    }

    function exceptionTenant() { return String((SAVED_FINDINGS && (SAVED_FINDINGS.TenantId || SAVED_FINDINGS.TenantName)) || "").toLowerCase(); }

    // FNV-1a hash of the exceptions of the file, to detect that the file changed since the local changes (like the worklist).
    function exceptionFingerprint() {
        var text = JSON.stringify(Object.keys(fileExceptions).sort().map(function (key) {
            return [key].concat(EXCEPTION_FIELDS.map(function (name) { return fileExceptions[key][name] || ""; }));
        }));
        var hash = 0x811c9dc5;
        for (var i = 0; i < text.length; i++) {
            hash ^= text.charCodeAt(i);
            hash = Math.imul(hash, 0x01000193) >>> 0;
        }
        return Object.keys(fileExceptions).length + "-" + hash.toString(16);
    }

    function loadExceptions() {
        exceptionsEnabled = savedFindingsState.status === "loaded";
        fileExceptions = {};
        exceptions = {};
        if (!exceptionsEnabled) return;
        SAVED_RULES.forEach(function (rule) {
            rule.exceptions.forEach(function (raw) {
                var entry = sanitizeException(raw);
                if (!entry.ok) return;
                fileExceptions[exceptionKey(entry.value)] = Object.assign(entry.value, { status: String(raw.Status || ""), matchedCount: Number(raw.MatchedCount) || 0 });
            });
        });
        Object.keys(fileExceptions).forEach(function (key) { exceptions[key] = sanitizeException(fileExceptions[key]).value; });
        exceptionFileChanged = false;
        heldExceptionChanges = null;
        migrateExceptionStore();
        var stored = null;
        try { stored = JSON.parse(localStorage.getItem(exceptionStoreKey()) || "null"); } catch (_) { stored = null; }
        if (!stored || typeof stored !== "object" || stored.tenant !== exceptionTenant()) return;
        // Local changes the file already has are dropped: an addition or change that is in the file now, and a
        // removal of an exception the file no longer has. The others stay pending.
        var changes = { upserts: Object.create(null), removals: [] };
        Object.keys(stored.upserts && typeof stored.upserts === "object" ? stored.upserts : {}).forEach(function (key) {
            var entry = sanitizeException(stored.upserts[key]);
            if (!entry.ok) return;
            var entryKey = exceptionKey(entry.value);
            if (fileExceptions[entryKey] && sameException(entry.value, fileExceptions[entryKey])) return;
            changes.upserts[entryKey] = entry.value;
        });
        (Array.isArray(stored.removals) ? stored.removals : []).forEach(function (key) {
            key = String(key);
            if (fileExceptions[key] && !changes.upserts[key] && changes.removals.indexOf(key) < 0) changes.removals.push(key);
        });
        var pending = Object.keys(changes.upserts).length + changes.removals.length > 0;
        // Pending changes made on another version of the file (or stored before the fingerprint existed) are flagged:
        // exporting them could revert changes of the file, for example a renewal by a teammate. Until they are kept
        // or discarded the file wins: they are not applied, and stay stored with the fingerprint of their file.
        if (pending && stored.baseFingerprint !== exceptionFingerprint()) {
            exceptionFileChanged = true;
            heldExceptionChanges = { baseFingerprint: typeof stored.baseFingerprint === "string" ? stored.baseFingerprint : "", upserts: changes.upserts, removals: changes.removals };
            return;
        }
        applyExceptionChanges(changes);
        saveExceptions();
    }

    // Storage key of the pending changes of a tenant (of the loaded results by default).
    function exceptionStoreKey(tenant) { return EXCEPTION_STORE_KEY + "." + (tenant == null ? exceptionTenant() : tenant); }

    // The v1 key held the pending changes of one tenant only: moved once to the key of their tenant, so the first
    // change in another tenant doesn't replace them.
    function migrateExceptionStore() {
        try {
            var raw = localStorage.getItem(LEGACY_EXCEPTION_STORE_KEY);
            if (raw == null) return;
            var legacy = null;
            try { legacy = JSON.parse(raw); } catch (_) { legacy = null; }
            if (legacy && typeof legacy === "object" && typeof legacy.tenant === "string" && localStorage.getItem(exceptionStoreKey(legacy.tenant)) == null) {
                localStorage.setItem(exceptionStoreKey(legacy.tenant), raw);
            }
            localStorage.removeItem(LEGACY_EXCEPTION_STORE_KEY);
        } catch (_) { /* private mode: nothing to migrate */ }
    }

    // Stored changes on top of the exceptions of this page; a change made on this page since then stays as it is.
    function applyExceptionChanges(changes) {
        changes.removals.forEach(function (key) { if (fileExceptions[key] && !exceptionChange(key)) delete exceptions[key]; });
        Object.keys(changes.upserts).forEach(function (key) { if (!exceptionChange(key)) exceptions[key] = changes.upserts[key]; });
    }

    function heldExceptionCount() {
        return exceptionFileChanged && heldExceptionChanges ? Object.keys(heldExceptionChanges.upserts).length + heldExceptionChanges.removals.length : 0;
    }

    // Only the changes against the file are stored, so exceptions added to the file elsewhere are never dropped.
    function saveExceptions() {
        var upserts = {}, removals = [];
        Object.keys(exceptions).forEach(function (key) { if (!fileExceptions[key] || !sameException(exceptions[key], fileExceptions[key])) upserts[key] = exceptions[key]; });
        Object.keys(fileExceptions).forEach(function (key) { if (!exceptions[key]) removals.push(key); });
        // The file changed and the stored changes are neither kept nor discarded yet: they stay stored, with the
        // fingerprint of their file, so the notice is shown again after a reload. Changes of this page come on top.
        var held = exceptionFileChanged ? heldExceptionChanges : null;
        if (held) {
            var changed = function (key) { return Object.prototype.hasOwnProperty.call(upserts, key) || removals.indexOf(key) >= 0; };
            Object.keys(held.upserts).filter(function (key) { return !changed(key); }).forEach(function (key) { upserts[key] = held.upserts[key]; });
            held.removals.filter(function (key) { return !changed(key); }).forEach(function (key) { removals.push(key); });
        }
        try {
            if (Object.keys(upserts).length || removals.length) localStorage.setItem(exceptionStoreKey(), JSON.stringify({ tenant: exceptionTenant(), baseFingerprint: held ? held.baseFingerprint : exceptionFingerprint(), upserts: upserts, removals: removals }));
            else localStorage.removeItem(exceptionStoreKey());
        } catch (_) { /* private mode: this page only */ }
    }

    function exceptionChange(key) {
        if (!fileExceptions[key]) return exceptions[key] ? "Added" : "";
        if (!exceptions[key]) return "Removed";
        return sameException(exceptions[key], fileExceptions[key]) ? "" : "Changed";
    }

    function exceptionExpired(entry) { return !!entry.ExpiresOn && entry.ExpiresOn < isoToday(); }

    function exceptionExpiring(entry) { return !!entry.ExpiresOn && !exceptionExpired(entry) && entry.ExpiresOn <= isoAddDays(isoToday(), EXPIRING_DAYS); }

    // Status of an exception: the local change, else the status of the last evaluation (expired since then included).
    function exceptionStatus(key) {
        var change = exceptionChange(key);
        if (change) return change;
        var file = fileExceptions[key];
        if (exceptionExpired(file)) return "Expired";
        return EXCEPTION_STATUS[file.status] ? file.status : "Active";
    }

    function exceptionKeys() {
        var entryOf = function (key) { return exceptions[key] || fileExceptions[key]; };
        return Array.from(new Set(Object.keys(exceptions).concat(Object.keys(fileExceptions)))).sort(function (a, b) {
            var left = entryOf(a), right = entryOf(b);
            return left.RuleId.localeCompare(right.RuleId) || (left.DisplayName || left.ObjectId || a).localeCompare(right.DisplayName || right.ObjectId || b);
        });
    }

    // The exception of this browser for a result of a check, like Split-EntraOpsFindingResultByException: of its
    // instance, else of its object - the first one that has not expired. Without one, an expired exception.
    function exceptionForResult(rule, result) {
        var keys = [];
        if (result.instanceId) keys.push([rule.id, result.instanceId, ""].join("|").toLowerCase());
        if (result.objectId) keys.push([rule.id, "", result.objectId].join("|").toLowerCase());
        var found = keys.filter(function (candidate) { return exceptions[candidate]; }).map(function (key) { return { key: key, entry: exceptions[key] }; });
        return found.filter(function (match) { return !exceptionExpired(match.entry); })[0] || found[0] || null;
    }

    // Privileged Assets findings evaluated in this browser (What-if) leave out the findings the file accepts.
    function acceptedInFile(ruleId, objectId) {
        return [[ruleId, objectId, ""], [ruleId, "", objectId]].some(function (parts) {
            var entry = fileExceptions[parts.join("|").toLowerCase()];
            return entry && !exceptionExpired(entry);
        });
    }

    function exceptionStateChip(entry) {
        return '<span class="chip pai-exception-state pai-exception-' + esc(entry.State.toLowerCase()) + '">' + esc(EXCEPTION_STATE_LABEL[entry.State] || entry.State) + "</span>";
    }

    function exceptionFileName() { return EXCEPTION_FILE.split(/[\\/]/).pop() || "FindingExceptions.json"; }

    function renderExceptions() {
        var visible = exceptionsEnabled && rules.length > 0;
        $("secPaiExceptions").hidden = !visible;
        if (!visible) return;
        var keys = exceptionKeys();
        var pending = keys.filter(exceptionChange).length;
        var held = heldExceptionCount();
        $("paiExceptionMeta").textContent = Object.keys(exceptions).length + " exceptions · " + pending + " pending changes" + (held ? " · " + held + " not applied" : "");
        $("paiExceptionExport").textContent = "Export " + exceptionFileName();
        // An export with the stored changes could undo changes of the file, one without them would lose them.
        $("paiExceptionExport").disabled = exceptionFileChanged;
        $("paiExceptionExport").title = exceptionFileChanged ? "Keep or discard the changes of this browser first: the exceptions file changed." : "";
        $("paiExceptionReset").disabled = !pending && !held;
        $("paiExceptionFileChanged").hidden = !exceptionFileChanged;
        $("paiExceptionFileChangedList").innerHTML = exceptionFileChanged && heldExceptionChanges ? Object.keys(heldExceptionChanges.upserts).map(function (key) {
            var entry = heldExceptionChanges.upserts[key];
            return "<li>" + esc((fileExceptions[key] ? "Change " : "Add ") + entry.RuleId + " · " + (entry.DisplayName || entry.ObjectId || entry.InstanceId) + " (" + (EXCEPTION_STATE_LABEL[entry.State] || entry.State) + (entry.ExpiresOn ? " until " + entry.ExpiresOn : "") + ")") + "</li>";
        }).concat(heldExceptionChanges.removals.map(function (key) {
            var entry = fileExceptions[key];
            return "<li>" + esc("Remove " + entry.RuleId + " · " + (entry.DisplayName || entry.ObjectId || entry.InstanceId)) + "</li>";
        })).join("") : "";
        $("paiExceptionStatus").innerHTML = "<b>Dismissed and risk-accepted findings</b> are listed in <code>" + esc(EXCEPTION_FILE) + "</code> (<code>Findings.ExceptionsFilePath</code>). " +
            "The evaluation doesn't report them: their check counts them apart, and the EntraOps Maester Pack doesn't fail for them. Accept a finding in the panel of its check. " +
            "Changes are kept in this browser until you export the file and save it as <code>" + esc(EXCEPTION_FILE) + "</code> in the EntraOps folder - commit it to the repository, or keep it in a local folder. " +
            "The next evaluation (<code>New-EntraOpsReportingData</code>) applies it." +
            (EXCEPTION_MAX_DAYS ? " A risk is accepted for at most " + esc(EXCEPTION_MAX_DAYS) + " days (<code>Findings.ExceptionMaxDays</code>)." : "") +
            (pending ? "<br><b>" + esc(pending) + " pending change" + (pending === 1 ? " is" : "s are") + " not in the file yet.</b>" : "");
        $("paiExceptionBody").innerHTML = keys.map(function (key) {
            var entry = exceptions[key] || fileExceptions[key];
            var status = exceptionStatus(key);
            var info = EXCEPTION_STATUS[status];
            var rule = ruleById[entry.RuleId];
            var object = objectsById[String(entry.ObjectId).toLowerCase()];
            var name = object ? '<button type="button" class="pai-link" data-open="' + esc(object.objectId) + '">' + esc(object.displayName) + "</button>" : esc(entry.DisplayName || entry.ObjectId || entry.InstanceId);
            var scope = entry.InstanceId ? "Finding " + entry.InstanceId : "All findings of the object";
            var check = rule ? '<button type="button" class="pai-link" data-rule-open="' + esc(rule.id) + '">' + esc(rule.id) + '</button><div class="muted pai-small">' + esc(rule.title) + "</div>" : esc(entry.RuleId);
            var expires = entry.ExpiresOn ? esc(entry.ExpiresOn) + (exceptionExpiring(entry) ? ' <span class="chip warn" title="Expires within ' + EXPIRING_DAYS + ' days">Soon</span>' : "") : '<span class="muted">-</span>';
            var details = [entry.AcceptedBy, entry.AcceptedOn, entry.Reference].filter(Boolean).join(" · ");
            var action = status === "Removed" ? '<button type="button" class="btn small" data-exception-restore="' + esc(key) + '">Restore</button>' : '<button type="button" class="btn small" data-exception-remove="' + esc(key) + '">Remove</button>';
            return '<tr data-exception="' + esc(key) + '"' + (status === "Removed" ? ' class="pai-removed"' : "") + "><td>" + check + "</td><td>" + name + '<div class="muted pai-small cell-truncate" title="' + esc(scope) + '">' + esc(scope) + "</div></td>" +
                '<td class="pai-nowrap">' + exceptionStateChip(entry) + '</td><td class="pai-nowrap">' + expires + '</td><td class="pai-wrap">' + esc(entry.Justification) + (details ? '<div class="muted pai-small">' + esc(details) + "</div>" : "") + "</td>" +
                '<td class="pai-nowrap"><span class="status-chip ' + info.cls + '" title="' + esc(info.title) + '">' + esc(info.label) + "</span></td><td>" + action + "</td></tr>";
        }).join("") || '<tr><td colspan="7" class="muted">No finding is dismissed or risk accepted. Open a failed check and select <i>Accept</i> at an affected object, or import a file.</td></tr>';
    }

    // After a change of the exceptions: the list, the tiles and the open check.
    function exceptionsChanged() {
        saveExceptions();
        renderExceptions();
        renderRuleStats();
        if (ruleBlade.ruleId && panelOpen("paiRuleBlade")) renderRuleResults();
    }

    // Discards the changes of this browser, the ones held back for a changed file included.
    function discardExceptionChanges() {
        if (!window.confirm("Discard the exception changes of this browser? The list shows the exceptions of the file again.")) return;
        exceptions = {};
        Object.keys(fileExceptions).forEach(function (key) { exceptions[key] = sanitizeException(fileExceptions[key]).value; });
        heldExceptionChanges = null;
        exceptionFileChanged = false;
        exceptionsChanged();
    }

    function exportExceptions() {
        // Not while the changed file and the changes of this browser are unresolved (the button is disabled, too).
        if (exceptionFileChanged) return;
        var list = exceptionKeys().filter(function (key) { return exceptions[key]; }).map(function (key) {
            var entry = {};
            EXCEPTION_FIELDS.forEach(function (name) { if (exceptions[key][name]) entry[name] = exceptions[key][name]; });
            return entry;
        });
        download(exceptionFileName(), "application/json", JSON.stringify(list, null, 2) + "\n");
    }

    function importExceptions(file) {
        var show = function (message, isWarning, details) {
            var result = $("paiExceptionImportResult");
            result.className = "pai-import-result callout" + (isWarning ? " scope" : "");
            result.innerHTML = esc(message) + (details && details.length ? '<ul class="pai-small">' + details.map(function (detail) { return "<li>" + esc(detail) + "</li>"; }).join("") + "</ul>" : "");
        };
        if (!file) return;
        if (file.size > MAX_IMPORT_BYTES) { show("The file is larger than 5 MB and was not imported.", true); return; }
        var reader = new FileReader();
        reader.onload = function () {
            var rows;
            try { rows = JSON.parse(String(reader.result)); } catch (error) { show("The file could not be parsed: " + error.message, true); return; }
            if (!Array.isArray(rows)) { show("The file must contain a JSON array of exceptions.", true); return; }
            if (rows.length > MAX_IMPORT_ROWS) { show("The file contains more than " + MAX_IMPORT_ROWS + " exceptions and was not imported.", true); return; }
            var accepted = 0, rejected = [], notes = [], noted = [];
            var note = function (index, value, text) {
                notes.push("Entry " + (index + 1) + " (" + value.RuleId + "): " + text);
                if (noted.indexOf(index) < 0) noted.push(index);
            };
            var today = isoToday();
            rows.forEach(function (row, index) {
                var entry = sanitizeException(row);
                if (entry.ok && !ruleById[entry.value.RuleId]) entry = { ok: false, reason: "unknown check " + entry.value.RuleId };
                if (!entry.ok) { rejected.push("Entry " + (index + 1) + ": " + entry.reason); return; }
                var value = entry.value;
                // Like Read-EntraOpsFindingExceptionFile, which warns for these dates and applies the exception as it is.
                if (value.AcceptedOn && value.ExpiresOn && value.ExpiresOn < value.AcceptedOn) note(index, value, "expires on " + value.ExpiresOn + ", before it was accepted on " + value.AcceptedOn + ". Check the dates.");
                if (value.AcceptedOn && value.AcceptedOn > today) note(index, value, "was accepted on " + value.AcceptedOn + ", a date in the future. Check the date.");
                // Like Read-EntraOpsFindingExceptionFile: a risk is accepted for at most MaxDays after AcceptedOn.
                var limit = EXCEPTION_MAX_DAYS && value.State === "RiskAccepted" ? isoAddDays(value.AcceptedOn, EXCEPTION_MAX_DAYS) : "";
                if (limit && value.ExpiresOn > limit) {
                    note(index, value, "expires on " + value.ExpiresOn + ", more than " + EXCEPTION_MAX_DAYS + " days after " + value.AcceptedOn + " - shortened to " + limit + ".");
                    value.ExpiresOn = limit;
                }
                if (value.Justification.length > EXCEPTION_FIELD_MAX.Justification) note(index, value, "the justification is longer than " + EXCEPTION_FIELD_MAX.Justification + " characters. It is kept and exported unchanged.");
                exceptions[exceptionKey(value)] = value;
                accepted++;
            });
            exceptionsChanged();
            var details = rejected.concat(notes);
            show("Imported " + accepted + " exceptions from " + file.name + "." + (rejected.length ? " Rejected " + rejected.length + " entries." : "") + (noted.length ? " " + noted.length + " entries were adjusted or need attention." : ""),
                details.length > 0, details.slice(0, 15));
        };
        reader.onerror = function () { show("The file could not be read.", true); };
        reader.readAsText(file);
    }

    // The form to accept a result of the open check (options.result, under its row) or the selected results
    // (options.bulk, above the list). Dismissed findings don't need an expiry date.
    function acceptFormHtml(options) {
        var bulk = options.bulk;
        var result = options.result;
        var object = result ? objectsById[result.objectId] : null;
        var name = result ? (object && object.displayName) || result.displayName || result.rawObjectId || result.instanceId : "";
        var today = isoToday();
        var max = EXCEPTION_MAX_DAYS ? isoAddDays(today, EXCEPTION_MAX_DAYS) : "";
        var by = "";
        try { by = localStorage.getItem(EXCEPTION_BY_KEY) || ""; } catch (_) { by = ""; }
        var objectCount = bulk ? distinctObjectCount(bulk) : 0;
        var scope = bulk ?
            '<label class="pai-check"><input type="radio" name="Scope" value="instance" checked /> Each selected finding (' + esc(bulk.length) + ")</label>" +
            '<label class="pai-check"><input type="radio" name="Scope" value="object" /> All findings of this check for the ' + esc(objectCount) + (objectCount === 1 ? " selected object" : " selected objects") + "</label>" :
            (result.instanceId ? '<label class="pai-check"><input type="radio" name="Scope" value="instance" checked /> This finding</label>' : "") +
            (result.rawObjectId ? '<label class="pai-check"><input type="radio" name="Scope" value="object"' + (result.instanceId ? "" : " checked") + " /> All findings of this check for " + esc(name) + "</label>" : "");
        return '<form class="pai-accept-form' + (bulk ? " pai-accept-bulk" : "") + '" id="' + (bulk ? "paiBulkAcceptForm" : "paiAcceptForm") + '" novalidate>' +
            (bulk ? '<div class="pai-accept-title"><b>Accept ' + esc(bulk.length) + " selected finding" + (bulk.length === 1 ? "" : "s") + "</b></div>" : "") +
            '<div class="pai-accept-grid">' +
            '<label>State<select class="pai-input" name="State"><option value="RiskAccepted">Risk accepted (until it expires)</option><option value="Dismissed">Dismissed (false positive)</option></select></label>' +
            '<label><span data-expires-label>Expires on</span><input type="date" class="pai-input" name="ExpiresOn" min="' + today + '"' + (max ? ' max="' + max + '"' : "") + ' value="' + defaultExpiry() + '" /></label>' +
            '<label>Accepted by<input type="text" class="pai-input" name="AcceptedBy" maxlength="256" value="' + esc(by) + '" placeholder="Name or user principal name" /></label>' +
            '<label>Reference<input type="text" class="pai-input" name="Reference" maxlength="256" placeholder="Change or ticket number" /></label>' +
            "</div>" +
            '<div class="pai-accept-scope" role="radiogroup" aria-label="Applies to"><span class="muted pai-small">Applies to</span>' + scope + "</div>" +
            '<label class="pai-accept-justification">Justification<textarea class="pai-input" name="Justification" rows="2" maxlength="' + EXCEPTION_FIELD_MAX.Justification + '" placeholder="Why the finding is accepted or a false positive"></textarea></label>' +
            '<div class="pai-error pai-small pai-accept-error" role="alert"></div>' +
            '<div class="pai-toolbar"><button type="submit" class="btn small primary">' + (bulk ? "Add " + esc(bulk.length) + " exceptions" : "Add exception") + '</button><button type="button" class="btn small" data-accept-cancel>Cancel</button></div>' +
            "</form>";
    }

    // The expiry date the form suggests for an accepted risk: 90 days, or MaxDays when it is shorter.
    function defaultExpiry() { return isoAddDays(isoToday(), EXCEPTION_MAX_DAYS ? Math.min(90, EXCEPTION_MAX_DAYS) : 90); }

    // Dismissed: the expiry date is optional and empty; an accepted risk needs one.
    function updateAcceptState(form) {
        var dismissed = form.elements.State.value === "Dismissed";
        var input = form.elements.ExpiresOn;
        if (dismissed && input.value === defaultExpiry()) input.value = "";
        if (!dismissed && !input.value) input.value = defaultExpiry();
        input.required = !dismissed;
        form.querySelector("[data-expires-label]").textContent = dismissed ? "Expires on (optional)" : "Expires on";
    }

    function resultId(result) { return result.instanceId || result.objectId; }

    // Why an exception of the form can't be added, or "".
    function exceptionEntryError(entry) {
        var today = isoToday();
        var max = EXCEPTION_MAX_DAYS ? isoAddDays(today, EXCEPTION_MAX_DAYS) : "";
        if (!entry.Justification) return "Enter a justification.";
        if (entry.State === "RiskAccepted" && !entry.ExpiresOn) return "A risk is accepted until a date: enter when it expires.";
        if (entry.ExpiresOn && !isIsoDate(entry.ExpiresOn)) return "Enter the expiry date as yyyy-mm-dd.";
        if (entry.ExpiresOn && entry.ExpiresOn < today) return "The expiry date is in the past.";
        if (entry.State === "RiskAccepted" && max && entry.ExpiresOn > max) return "A risk is accepted for at most " + EXCEPTION_MAX_DAYS + " days (until " + max + ").";
        return "";
    }

    function submitAcceptForm(form) {
        var rule = ruleById[ruleBlade.ruleId];
        if (!rule) return;
        var bulk = form.id === "paiBulkAcceptForm";
        var targets = bulk ? selectedResults(rule) : openResults(rule).filter(function (candidate) { return resultId(candidate) === ruleBlade.acceptFor; }).slice(0, 1);
        if (!targets.length) return;
        var field = function (name) { return form.elements[name] ? String(form.elements[name].value || "").trim() : ""; };
        var scope = form.querySelector('input[name="Scope"]:checked');
        var objectScope = scope && scope.value === "object";
        var template = {
            RuleId: rule.id, State: field("State"), Justification: field("Justification"), AcceptedBy: field("AcceptedBy"), AcceptedOn: isoToday(), ExpiresOn: field("ExpiresOn"), Reference: field("Reference")
        };
        // One exception per finding, or per object with the object scope (also for results without an instance ID).
        var entries = {}, error = exceptionEntryError(template);
        targets.forEach(function (result) {
            if (error) return;
            var entry = Object.assign({}, template, {
                InstanceId: objectScope || !result.instanceId ? "" : result.instanceId, ObjectId: result.rawObjectId,
                DisplayName: (objectsById[result.objectId] || {}).displayName || result.displayName || ""
            });
            var checked = sanitizeException(entry);
            if (!checked.ok) { error = checked.reason; return; }
            entries[exceptionKey(checked.value)] = checked.value;
        });
        if (error) { form.querySelector(".pai-accept-error").textContent = error; return; }
        Object.keys(entries).forEach(function (key) { exceptions[key] = entries[key]; });
        try { if (template.AcceptedBy) localStorage.setItem(EXCEPTION_BY_KEY, template.AcceptedBy); } catch (_) { /* private mode */ }
        ruleBlade.acceptFor = "";
        ruleBlade.bulkOpen = false;
        ruleBlade.selected = Object.create(null);
        exceptionsChanged();
    }

    // Exception cell of an affected object in the panel of a check: the exception that applies (pending changes with
    // Undo), else Accept… and the checkbox for a bulk exception.
    function resultExceptionCell(rule, result) {
        if (result.unclassified) return "";
        if (acceptedNow(result)) {
            var accepted = result.exception;
            var until = accepted.ExpiresOn ? '<div class="muted pai-small">until ' + esc(accepted.ExpiresOn) + "</div>" : "";
            var removal = accepted.Key && exceptionChange(accepted.Key) === "Removed" ? '<div class="muted pai-small">Removal pending</div>' : "";
            return '<span title="' + esc(accepted.Justification || "") + '">' + exceptionStateChip({ State: accepted.State || "" }) + "</span>" + until + removal;
        }
        var id = resultId(result);
        var select = resultSelectable(rule, result) ? '<label class="pai-check pai-rres-select"><input type="checkbox" data-select-result="' + esc(id) + '"' + (ruleBlade.selected[id] ? " checked" : "") + ' aria-label="Select this finding" /> Select</label>' : "";
        var button = ruleBlade.acceptFor === id ? "" : '<button type="button" class="btn small" data-accept="' + esc(id) + '" title="Dismiss or accept the risk of this finding">Accept…</button>';
        // Accepted at the last evaluation by an exception that has expired since then: not accepted any more.
        var stale = result.exception ? '<span class="chip warn pai-exception-state pai-exception-expired" title="' + esc(result.exception.Justification || "") + '">Exception expired ' + esc(String(result.exception.ExpiresOn).slice(0, 10)) + "</span>" +
            '<div class="muted pai-small">Accepted at the last evaluation</div>' : "";
        var match = exceptionForResult(rule, result);
        if (!match) return stale + button + select;
        // Added or changed in this browser: pending until the next evaluation. Undo restores the file entry.
        var change = exceptionChange(match.key);
        var chip = '<span title="' + esc(match.entry.Justification) + '">' + exceptionStateChip(match.entry) + "</span>";
        if (stale && !change && exceptionExpired(match.entry)) return stale + button + select;
        chip = stale + chip;
        if (change) return chip + '<div class="muted pai-small">Pending - export the file</div><button type="button" class="btn small pai-exception-undo" ' +
            (change === "Changed" ? "data-exception-restore" : "data-exception-remove") + '="' + esc(match.key) + '">Undo</button>';
        // An expired exception of the file: the finding is reported again, and can be accepted again.
        if (exceptionExpired(match.entry)) return chip + '<div class="muted pai-small">Expired</div>' + button + select;
        // In the file, but not applied by the evaluation of these results yet.
        return chip + '<div class="muted pai-small">Applies at the next evaluation</div>';
    }

    // Info bar of a check with accepted results: they're counted apart, and listed on request.
    function ruleAcceptedInfo(rule) {
        var acceptance = ruleAcceptance(rule);
        // Expired exceptions: the saved status and counts are outdated, which the panel says instead of recomputing them.
        var stale = acceptance.expired ? '<div class="callout scope pai-rule-expired" role="status"><b>Results of the last evaluation.</b> ' + esc(ruleStaleNote(rule)) + "</div>" : "";
        if (!acceptance.accepted) return stale;
        var risks = acceptance.risks;
        var parts = [risks ? risks + " risk accepted" : "", acceptance.dismissed ? acceptance.dismissed + " dismissed as false positive" + (acceptance.dismissed === 1 ? "" : "s") : ""].filter(Boolean).join(", ");
        return stale + '<div class="callout pai-rule-accepted" role="status"><b>' + esc(acceptance.accepted) + " accepted finding" + (acceptance.accepted === 1 ? "" : "s") + "</b> (" + esc(parts) + ") in <code>" + esc(EXCEPTION_FILE) + "</code>, not counted." +
            (risks && rule.status === "Passed" ? " The check passes only because risks are accepted: the control is not met, and the EntraOps Maester Pack skips its test." : "") +
            (rule.acceptedResults.some(acceptedNow) ? '<label class="pai-check pai-rule-unclassified-toggle"><input type="checkbox" id="paiRuleShowAccepted"' + (ruleBlade.showAccepted ? " checked" : "") + " /> Show accepted findings in the list</label>" : "") + "</div>";
    }

    // ---- Import / export ------------------------------------------------------------------------
    function csvCell(value) {
        var text = value == null ? "" : String(value);
        if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
        return '"' + text.replace(/"/g, '""') + '"';
    }

    function toCsv(headers, rows) {
        return headers.map(csvCell).join(",") + "\r\n" + rows.map(function (row) { return headers.map(function (header) { return csvCell(row[header]); }).join(","); }).join("\r\n") + "\r\n";
    }

    function parseCsv(text) {
        var firstLine = text.split(/\r?\n/, 1)[0] || "";
        var delimiter = firstLine.indexOf(";") >= 0 && firstLine.indexOf(",") < 0 ? ";" : ",";
        var rows = [], row = [], field = "", inQuotes = false;
        for (var i = 0; i < text.length; i++) {
            var c = text[i];
            if (inQuotes) {
                if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
                else if (c === '"') inQuotes = false;
                else field += c;
            } else if (c === '"') inQuotes = true;
            else if (c === delimiter) { row.push(field); field = ""; }
            else if (c === "\n" || c === "\r") {
                if (c === "\r" && text[i + 1] === "\n") i++;
                row.push(field); field = "";
                if (row.some(function (value) { return value !== ""; })) rows.push(row);
                row = [];
            } else field += c;
        }
        row.push(field);
        if (row.some(function (value) { return value !== ""; })) rows.push(row);
        if (!rows.length) return [];
        var headers = rows.shift().map(function (header) { return header.replace(/^\uFEFF/, "").trim(); });
        return rows.map(function (values) {
            var record = {};
            headers.forEach(function (header, index) { record[header] = values[index]; });
            return record;
        });
    }

    function download(name, type, content) {
        var link = document.createElement("a");
        var href = URL.createObjectURL(new Blob([content], { type: type }));
        link.href = href;
        link.download = name;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(href); }, 1000);
    }

    function fileRows() {
        return Object.keys(state.worklistEntries).sort().map(function (id) {
            var entry = state.worklistEntries[id];
            return { ObjectId: entry.objectId, ObjectType: entry.objectType, ObjectDisplayName: entry.objectDisplayName, AdminTierLevelName: entry.adminTierLevelName, Justification: entry.justification };
        });
    }

    function fileBaseName() {
        var path = ((DATA.classificationSettings || {}).objectClassificationFile || {}).filePath || "ObjectClassification.json";
        var name = path.split(/[\\/]/).pop() || "ObjectClassification.json";
        return name.replace(/\.(json|csv)$/i, "");
    }

    function importFile(file) {
        var result = $("paiImportResult");
        if (!file) return;
        if (file.size > MAX_IMPORT_BYTES) {
            showImportResult("The file is larger than 5 MB and was not imported.", true);
            return;
        }
        var reader = new FileReader();
        reader.onload = function () {
            var rows;
            try {
                rows = /\.json$/i.test(file.name) ? JSON.parse(String(reader.result)) : parseCsv(String(reader.result));
            } catch (error) {
                showImportResult("The file could not be parsed: " + error.message, true);
                return;
            }
            if (!Array.isArray(rows)) { showImportResult("The file must contain an array (JSON) or rows with a header line (CSV).", true); return; }
            if (rows.length > MAX_IMPORT_ROWS) { showImportResult("The file contains more than " + MAX_IMPORT_ROWS + " rows and was not imported.", true); return; }
            var accepted = 0, rejected = [];
            rows.forEach(function (row, index) {
                var entry = sanitizeEntry(row);
                if (entry.ok) { state.worklistEntries[entry.value.objectId] = entry.value; accepted++; }
                else rejected.push("Row " + (index + 1) + ": " + entry.reason);
            });
            saveWorklist();
            renderAll();
            showImportResult("Imported " + accepted + " entries from " + file.name + "." + (rejected.length ? " Rejected " + rejected.length + " rows:" : ""), rejected.length > 0, rejected.slice(0, 10));
        };
        reader.onerror = function () { showImportResult("The file could not be read.", true); };
        reader.readAsText(file);
        result.classList.add("hidden");
    }

    function showImportResult(message, isWarning, details) {
        var result = $("paiImportResult");
        result.className = "pai-import-result callout" + (isWarning ? " scope" : "");
        result.innerHTML = esc(message) + (details && details.length ? '<ul class="pai-small">' + details.map(function (detail) { return "<li>" + esc(detail) + "</li>"; }).join("") + "</ul>" : "");
    }

    function exportInventory() {
        var headers = ["ObjectId", "DisplayName", "UserPrincipalName", "ObjectType", "ObjectSubType", "ObjectTier", "TargetTier", "HighestAssignmentTier", "Assignments", "EligibleAssignments", "RoleSystems", "Owners", "Sponsors", "OwnedObjects", "OwnedDevices", "IdentityParent", "AdministrativeUnits", "RestrictedManagement", "SyncSource", "Findings", "FindingRules", "HighestSeverity", "MaesterFindings"];
        var names = function (ids) { return (ids || []).map(function (id) { return relatedInfo(id).displayName; }).join("; "); };
        var rows = filteredObjects().map(function (object) {
            var entry = state.worklistEntries[object.objectId];
            return {
                ObjectId: object.objectId, DisplayName: object.displayName, UserPrincipalName: object.userPrincipalName, ObjectType: object.objectType, ObjectSubType: object.objectSubType,
                ObjectTier: TIER_LABEL[object.tierName] || TIER_LABEL.Unclassified, TargetTier: entry ? TIER_LABEL[entry.adminTierLevelName] || entry.adminTierLevelName : "",
                HighestAssignmentTier: TIER_LABEL[object.assignmentSummary.highestTierName] || object.assignmentSummary.highestTierName,
                Assignments: object.assignmentSummary.total, EligibleAssignments: object.assignmentSummary.eligible, RoleSystems: (object.roleSystems || []).join("; "),
                Owners: names(object.owners), Sponsors: names(object.sponsors), OwnedObjects: names(object.ownedObjects), OwnedDevices: names(object.ownedDevices),
                IdentityParent: object.identityParent ? relatedInfo(object.identityParent).displayName : "",
                AdministrativeUnits: (object.administrativeUnits || []).map(function (unit) { return unit.displayName || unit.id; }).join("; "),
                RestrictedManagement: object.restrictedManagement, SyncSource: object.onPremSynchronized ? "Hybrid" : "Cloud-only",
                Findings: object._items.map(function (item) { return item.label; }).join("; "),
                FindingRules: object._items.map(function (item) { return item.ruleId; }).filter(Boolean).join("; "),
                // The most severe finding of the EntraOps checks and Maester tests, like the Findings column.
                HighestSeverity: object._items.length || object._maester.length ? SEVERITIES[topSeverityRank(object)] || "Unknown" : "",
                MaesterFindings: object._maester.map(function (finding) { return finding.testId + " (" + maesterSeverityLabel(finding.test) + ")"; }).join("; ")
            };
        });
        download("PrivilegedAssets.csv", "text/csv;charset=utf-8", toCsv(headers, rows));
    }

    // ---- PowerShell script generation -----------------------------------------------------------
    function psLiteral(value) {
        return "'" + String(value).replace(/['\u2018\u2019\u201A\u201B]/g, "''") + "'";
    }

    function safeName(value) {
        return String(value || "").replace(/[^\p{L}\p{N} ._@()\-]/gu, "_").slice(0, 120);
    }

    function generateScript() {
        var settings = DATA.classificationSettings || {};
        var csa = settings.customSecurityAttributes || {};
        var attributes = {
            user: { set: csa.userAttributeSet, level: csa.userTierLevelAttribute, name: csa.userTierNameAttribute },
            servicePrincipal: { set: csa.servicePrincipalAttributeSet, level: csa.servicePrincipalTierLevelAttribute, name: csa.servicePrincipalTierNameAttribute }
        };
        var warnings = [];
        var invalid = Object.keys(attributes).filter(function (kind) {
            var attribute = attributes[kind];
            return ![attribute.set, attribute.level, attribute.name].every(function (value) { return CSA_NAME.test(value || ""); });
        });

        var restrictToSelection = $("paiScriptSelectedOnly").checked;
        var changes = [], skipped = [], ignoredTypes = [];
        Object.keys(state.worklistEntries).sort().forEach(function (id) {
            if (restrictToSelection && !state.selected.has(id)) return;
            var entry = state.worklistEntries[id];
            var object = objectsById[id];
            var name = object ? object.displayName : entry.objectDisplayName;
            if (!object) { skipped.push(safeName(name || id) + " (" + id + "): not in the Privileged EAM export"); return; }
            var current = TIER_LABEL[object.tierName] ? object.tierName : "Unclassified";
            if (current === entry.adminTierLevelName) return;
            if (object.objectType === "group") { skipped.push(safeName(name) + " (" + id + "): groups don't support custom security attributes - use the Object Classification File"); return; }
            if (inOtherTenant(object)) { skipped.push(safeName(name) + " (" + id + "): belongs to another tenant - custom security attributes can only be set on objects of the home tenant"); return; }
            var kind = object.objectType === "user" ? "user" : "servicePrincipal";
            var uri;
            if (object.objectType === "user") uri = "users/" + id;
            else if (object.objectType === "serviceprincipal") uri = "servicePrincipals/" + id;
            else if (object.objectType === "application" && GUID.test(object.userPrincipalName || "")) uri = "servicePrincipals(appId='" + object.userPrincipalName.toLowerCase() + "')";
            else { skipped.push(safeName(name) + " (" + id + "): unsupported object type or missing app id"); return; }
            if (!GUID.test(id) || !TIER_TAG[entry.adminTierLevelName]) { skipped.push(id + ": invalid entry"); return; }
            if (invalid.indexOf(kind) >= 0) { skipped.push(safeName(name) + " (" + id + "): custom security attribute names for " + kind + " are missing or invalid in EntraOpsConfig.json"); return; }
            changes.push({ kind: kind, uri: uri, name: safeName(name), current: current, tierLevel: TIER_TAG[entry.adminTierLevelName], tierName: entry.adminTierLevelName });
            var csaTypeKey = object.objectType === "serviceprincipal" ? "servicePrincipal" : object.objectType;
            if (CSA_ENABLED_FOR[csaTypeKey] !== true && ignoredTypes.indexOf(TYPE_LABEL[object.objectType]) < 0) ignoredTypes.push(TYPE_LABEL[object.objectType]);
        });
        if (ignoredTypes.length) warnings.push("Custom security attributes are not used for the object type(s) " + ignoredTypes.join(", ") + " in EntraOpsConfig.json, so the script values will not change their EntraOps classification. Set CustomSecurityAttributes.Enabled to true to use them.");

        $("paiScriptWarning").classList.toggle("hidden", !warnings.length);
        $("paiScriptWarning").textContent = warnings.join(" ");
        if (!changes.length) {
            state.script = "";
            $("paiScript").value = "";
            $("paiScriptSummary").textContent = "No custom security attribute changes to generate." + (skipped.length ? " Skipped: " + skipped.join("; ") : " Add users, service principals or applications with a target tier that differs from the current tier to the worklist.");
            $("paiCopyScript").disabled = true;
            $("paiDownloadScript").disabled = true;
            return;
        }

        var kinds = Array.from(new Set(changes.map(function (change) { return change.kind; })));
        var lines = [];
        lines.push("<#");
        lines.push(".SYNOPSIS");
        lines.push("    Sets the EntraOps admin tier custom security attributes for " + changes.length + " object(s).");
        lines.push(".DESCRIPTION");
        lines.push("    Generated by EntraOps Privileged Assets" + (DATA.tenantName ? " for " + safeName(DATA.tenantName) : "") + " on " + new Date().toISOString() + ".");
        lines.push("    Review every change and run with -WhatIf first. Both fields of the tier pair are always written together.");
        lines.push("    Pasted into a console, the last line asks for confirmation per object; run Set-EntraOpsAdminTierAttribute -WhatIf instead to preview.");
        lines.push("    Requires the Microsoft.Graph.Authentication module, the delegated permissions");
        lines.push("    CustomSecAttributeAssignment.ReadWrite.All and CustomSecAttributeDefinition.Read.All,");
        lines.push("    and the Microsoft Entra role Attribute Assignment Administrator.");
        if (skipped.length) {
            lines.push("    Skipped objects:");
            skipped.forEach(function (item) { lines.push("      - " + item); });
        }
        lines.push("#>");
        lines.push("#Requires -Modules Microsoft.Graph.Authentication");
        lines.push("[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]");
        lines.push("param ()");
        lines.push("");
        lines.push("# A function keeps -WhatIf/-Confirm working when the script is pasted instead of run as a file.");
        lines.push("function Set-EntraOpsAdminTierAttribute {");
        lines.push("    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]");
        lines.push("    param ()");
        lines.push("");
        var header = lines;
        lines = [];
        lines.push("$ErrorActionPreference = 'Stop'");
        var tenantId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(DATA.homeTenantId || "") ? DATA.homeTenantId : "";
        lines.push("Connect-MgGraph -Scopes 'CustomSecAttributeAssignment.ReadWrite.All', 'CustomSecAttributeDefinition.Read.All'" + (tenantId ? " -TenantId '" + tenantId + "'" : "") + " -NoWelcome");
        lines.push("");
        lines.push("$Attributes = @{");
        kinds.forEach(function (kind) {
            var attribute = attributes[kind];
            lines.push("    " + kind + " = @{ Set = " + psLiteral(attribute.set) + "; Level = " + psLiteral(attribute.level) + "; Name = " + psLiteral(attribute.name) + " }");
        });
        lines.push("}");
        lines.push("");
        lines.push("foreach ($Attribute in $Attributes.Values) {");
        lines.push("    foreach ($Field in @($Attribute.Level, $Attribute.Name)) {");
        lines.push("        $Definition = Invoke-MgGraphRequest -Method GET -Uri \"https://graph.microsoft.com/v1.0/directory/customSecurityAttributeDefinitions/$($Attribute.Set)_$Field\"");
        lines.push("        $AllowedTypes = if ($Field -eq $Attribute.Level) { @('Integer', 'String') } else { @('String') }");
        lines.push("        if ($Definition.type -notin $AllowedTypes -or $Definition.isCollection -or $Definition.status -ne 'Available') {");
        lines.push("            throw \"Custom security attribute $($Attribute.Set)_$Field must be an available, single-valued $($AllowedTypes -join ' or ') attribute (type: $($Definition.type), collection: $($Definition.isCollection), status: $($Definition.status)).\"");
        lines.push("        }");
        lines.push("        if ($Field -eq $Attribute.Level) { $Attribute.LevelType = $Definition.type }");
        lines.push("    }");
        lines.push("}");
        lines.push("");
        lines.push("$Changes = @(");
        changes.forEach(function (change) {
            lines.push("    [pscustomobject]@{ Kind = " + psLiteral(change.kind) + "; Uri = " + psLiteral(change.uri) + "; DisplayName = " + psLiteral(change.name) + "; CurrentTier = " + psLiteral(change.current) + "; TierLevel = " + psLiteral(change.tierLevel) + "; TierName = " + psLiteral(change.tierName) + " }");
        });
        lines.push(")");
        lines.push("");
        lines.push("foreach ($Change in $Changes) {");
        lines.push("    $Attribute = $Attributes[$Change.Kind]");
        lines.push("    $Uri = \"https://graph.microsoft.com/v1.0/$($Change.Uri)\"");
        lines.push("    $Current = Invoke-MgGraphRequest -Method GET -Uri \"$($Uri)?`$select=id,customSecurityAttributes\"");
        lines.push("    $CurrentValues = if ($Current.customSecurityAttributes) { $Current.customSecurityAttributes[$Attribute.Set] }");
        lines.push("    $Before = if ($CurrentValues) { \"$($CurrentValues[$Attribute.Level]) / $($CurrentValues[$Attribute.Name])\" } else { 'not set' }");
        lines.push("    $Value = @{ '@odata.type' = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue' }");
        lines.push("    if ($Attribute.LevelType -eq 'Integer') {");
        lines.push("        $Value[\"$($Attribute.Level)@odata.type\"] = '#Int32'");
        lines.push("        $Value[$Attribute.Level] = [int]$Change.TierLevel");
        lines.push("    } else {");
        lines.push("        $Value[$Attribute.Level] = $Change.TierLevel");
        lines.push("    }");
        lines.push("    $Value[$Attribute.Name] = $Change.TierName");
        lines.push("    $Body = @{ customSecurityAttributes = @{ ($Attribute.Set) = $Value } } | ConvertTo-Json -Depth 5");
        lines.push("    if ($PSCmdlet.ShouldProcess(\"$($Change.DisplayName) ($($Change.Uri))\", \"Set $($Attribute.Set) tier from '$Before' to '$($Change.TierLevel) / $($Change.TierName)'\")) {");
        lines.push("        Invoke-MgGraphRequest -Method PATCH -Uri $Uri -Body $Body -ContentType 'application/json' | Out-Null");
        lines.push("        Write-Host \"Updated $($Change.DisplayName): $Before -> $($Change.TierLevel) / $($Change.TierName)\"");
        lines.push("    }");
        lines.push("}");
        lines = header.concat(lines.map(function (line) { return line ? "    " + line : ""; }), ["}", "", "Set-EntraOpsAdminTierAttribute"]);
        state.script = lines.join("\r\n") + "\r\n";
        $("paiScript").value = state.script;
        $("paiScriptSummary").textContent = changes.length + " change(s) generated" + (skipped.length ? ", " + skipped.length + " object(s) skipped (listed in the script header)." : ".");
        $("paiCopyScript").disabled = false;
        $("paiDownloadScript").disabled = false;
    }

    // ---- Wiring ---------------------------------------------------------------------------------
    // Select filters; object type, sub type and classification are pills (renderFacets).
    var FILTER_CONTROLS = { paiFilterAssignmentTier: "assignmentTier", paiFilterAu: "au", paiFilterRestricted: "restricted", paiFilterSync: "sync", paiFilterFinding: "finding", paiFilterWorklist: "worklist" };

    function syncFilterControls() {
        Object.keys(FILTER_CONTROLS).forEach(function (id) { $(id).value = filters[FILTER_CONTROLS[id]]; });
        $("paiSearch").value = state.search;
        $("paiWhatIf").checked = state.whatIf;
    }

    function setMoreFilters(open) {
        $("paiMoreFilterPanel").hidden = !open;
        $("paiMoreFilters").setAttribute("aria-expanded", String(open));
    }

    function resetFilters(render) {
        Object.keys(filters).forEach(function (key) { filters[key] = ""; });
        state.search = "";
        state.page = 0;
        if (render !== false) { syncFilterControls(); renderInventory(); }
    }

    function selectedIds() { return Array.from(state.selected); }

    function wire() {
        Object.keys(FILTER_CONTROLS).forEach(function (id) {
            $(id).addEventListener("change", function () { filters[FILTER_CONTROLS[id]] = $(id).value; state.page = 0; renderInventory(); });
        });
        $("paiSearch").addEventListener("input", function () { state.search = $("paiSearch").value.trim().toLowerCase(); state.page = 0; renderInventory(); });
        $("paiWhatIf").addEventListener("change", function () { state.whatIf = $("paiWhatIf").checked; renderAll(); });
        $("paiResetFilters").addEventListener("click", function () { resetFilters(); });
        $("paiMoreFilters").addEventListener("click", function () { setMoreFilters($("paiMoreFilterPanel").hidden); });
        EntraOpsFilters.bindPills($("paiTypePills").closest(".eo-facets"), filters, function (facet) {
            if (facet === "type") filters.subType = "";
            state.page = 0;
            renderInventory();
        });
        $("paiExportInventory").addEventListener("click", exportInventory);

        document.querySelectorAll("#paiTable thead th[data-sort]").forEach(function (th) {
            th.addEventListener("click", function () {
                var key = th.getAttribute("data-sort");
                state.sortDir = state.sort === key ? -state.sortDir : 1;
                state.sort = key;
                renderInventory();
            });
        });
        $("paiTableBody").addEventListener("change", function (ev) {
            var id = ev.target.getAttribute("data-select");
            if (!id) return;
            if (ev.target.checked) state.selected.add(id); else state.selected.delete(id);
            renderInventory();
        });
        $("paiSelectAll").addEventListener("change", function () {
            filteredObjects().forEach(function (object) {
                if ($("paiSelectAll").checked) state.selected.add(object.objectId); else state.selected.delete(object.objectId);
            });
            renderInventory();
        });
        $("paiPager").addEventListener("click", function (ev) {
            var step = ev.target.getAttribute("data-page");
            if (!step) return;
            state.page += Number(step);
            renderInventory();
        });
        document.addEventListener("click", function (ev) {
            var maesterOpener = ev.target.closest ? ev.target.closest("[data-maester-open]") : null;
            if (maesterOpener) { openMaesterBlade(maesterOpener.getAttribute("data-maester-open"), maesterOpener.getAttribute("data-maester-object"), true); return; }
            var findingsMore = ev.target.closest ? ev.target.closest("[data-findings-more]") : null;
            if (findingsMore) {
                openDrawer(findingsMore.getAttribute("data-findings-more"), "replace");
                var section = $("paiDrawerFindings") || $("paiDrawerMaester");
                if (section) section.scrollIntoView({ block: "start" });
                return;
            }
            // A check opened from an object (or from another view) is a new history entry: Back returns to the object.
            var ruleOpener = ev.target.closest ? ev.target.closest("[data-rule-open]") : null;
            if (ruleOpener) {
                var ruleId = ruleOpener.getAttribute("data-rule-open");
                if (!findRule(ruleId)) return;
                var push = ruleOpener.closest("#paiDrawer") || viewFromUrl() !== "findings";
                setView("findings", false);
                openRuleBlade(ruleId, push ? "push" : "replace");
                closeDrawer(false);
                return;
            }
            var opener = ev.target.closest ? ev.target.closest("[data-open]") : null;
            if (opener) {
                var fromRule = opener.closest("#paiRuleBlade");
                closeMaesterBlade(false);
                closeRuleBlade(false);
                openDrawer(opener.getAttribute("data-open"), fromRule ? "push" : "replace");
                return;
            }
            var exceptionRemove = ev.target.closest ? ev.target.closest("[data-exception-remove]") : null;
            if (exceptionRemove) { delete exceptions[exceptionRemove.getAttribute("data-exception-remove")]; exceptionsChanged(); return; }
            var exceptionRestore = ev.target.closest ? ev.target.closest("[data-exception-restore]") : null;
            if (exceptionRestore) {
                var exceptionKeyValue = exceptionRestore.getAttribute("data-exception-restore");
                if (fileExceptions[exceptionKeyValue]) { exceptions[exceptionKeyValue] = sanitizeException(fileExceptions[exceptionKeyValue]).value; exceptionsChanged(); }
                return;
            }
            var remove = ev.target.closest ? ev.target.closest("[data-remove]") : null;
            if (remove) { removeFromWorklist([remove.getAttribute("data-remove")]); renderAll(); return; }
            var restore = ev.target.closest ? ev.target.closest("[data-restore]") : null;
            if (restore) {
                var id = restore.getAttribute("data-restore");
                if (fileEntries[id]) { state.worklistEntries[id] = JSON.parse(JSON.stringify(fileEntries[id])); saveWorklist(); renderAll(); }
            }
        });

        $("paiBulkAdd").addEventListener("click", function () {
            if (!state.selected.size) return;
            setTargetTier(selectedIds(), $("paiBulkTier").value, $("paiBulkJustification").value);
            renderAll();
        });
        $("paiBulkRemove").addEventListener("click", function () { removeFromWorklist(selectedIds()); renderAll(); });
        $("paiBulkClear").addEventListener("click", function () { state.selected.clear(); renderInventory(); });

        $("paiAddButton").addEventListener("click", addObjectFromInput);
        $("paiAddObject").addEventListener("keydown", function (ev) { if (ev.key === "Enter") { ev.preventDefault(); addObjectFromInput(); } });
        $("paiWorklistBody").addEventListener("change", function (ev) {
            var tierId = ev.target.getAttribute("data-target-tier"), justificationId = ev.target.getAttribute("data-justification");
            var id = tierId || justificationId;
            var entry = id && state.worklistEntries[id];
            if (!entry) return;
            if (tierId && normalizeTier(ev.target.value)) entry.adminTierLevelName = normalizeTier(ev.target.value);
            if (justificationId) {
                // Update in place: re-rendering the table would drop the focus or click that ended the edit.
                entry.justification = ev.target.value.trim().slice(0, 500);
                saveWorklist();
                var chip = ev.target.closest("tr").querySelector(".status-chip");
                if (chip) chip.outerHTML = worklistStatusChip(worklistStatus(id));
                renderWorklistMeta();
                renderStats();
                renderInventory();
                return;
            }
            saveWorklist();
            renderAll();
            var select = document.querySelector('[data-target-tier="' + id + '"]');
            if (select) select.focus();
        });
        document.querySelectorAll("a[data-view-link]").forEach(function (link) {
            link.addEventListener("click", function (ev) {
                ev.preventDefault();
                setView(link.getAttribute("data-view-link"), true);
                window.scrollTo(0, 0);
            });
        });
        // Back, Forward and edited hashes close the open panels and apply the view and panel of the URL.
        window.addEventListener("popstate", applyUrl);

        $("paiImport").addEventListener("change", function () { importFile($("paiImport").files[0]); $("paiImport").value = ""; });
        $("paiExportCsv").addEventListener("click", function () {
            download(fileBaseName() + ".csv", "text/csv;charset=utf-8", toCsv(["ObjectId", "ObjectType", "ObjectDisplayName", "AdminTierLevelName", "Justification"], fileRows()));
        });
        $("paiExportFile").addEventListener("click", function () {
            download(fileBaseName() + ".json", "application/json;charset=utf-8", JSON.stringify(fileRows(), null, 2) + "\n");
        });
        $("paiResetWorklist").addEventListener("click", confirmResetWorklist);
        $("paiFileChangedReset").addEventListener("click", function () { if (confirmResetWorklist()) $("paiExportFile").focus(); });
        $("paiFileChangedKeep").addEventListener("click", function () {
            // Re-saving bases the local delta on the current repository file, which acknowledges the change.
            saveWorklist();
            state.fileChanged = false;
            renderAll();
            $("paiExportFile").focus();
        });
        $("paiClearWorklist").addEventListener("click", function () {
            if (!window.confirm("Remove all entries from the worklist? Download the file afterwards to remove them from the repository.")) return;
            state.worklistEntries = {};
            saveWorklist();
            renderAll();
        });

        $("paiGenerateScript").addEventListener("click", generateScript);
        $("paiCopyScript").addEventListener("click", function () {
            if (navigator.clipboard && state.script) navigator.clipboard.writeText(state.script).catch(function () { $("paiScript").select(); });
            else $("paiScript").select();
        });
        $("paiDownloadScript").addEventListener("click", function () {
            if (state.script) download("Set-EntraOpsObjectTierCustomSecurityAttributes.ps1", "text/plain;charset=utf-8", state.script);
        });

        $("paiDrawerClose").addEventListener("click", function () { closeDrawer(); });
        $("paiDrawerBackdrop").addEventListener("click", function () { closeDrawer(); });
        $("paiMaesterClose").addEventListener("click", function () { closeMaesterBlade(true); });
        $("paiMaesterBackdrop").addEventListener("click", function () { closeMaesterBlade(true); });
        document.addEventListener("keydown", function (ev) {
            if (ev.key !== "Escape") return;
            if ($("paiRuleBlade").classList.contains("open")) closeRuleBlade(true);
            else if ($("paiMaesterBlade").classList.contains("open")) closeMaesterBlade(true);
            else if ($("paiDrawer").classList.contains("open")) closeDrawer();
        });
        document.addEventListener("keydown", trapFocus);
        window.addEventListener("hashchange", applyUrl);

        // Findings view.
        $("paiRuleSearch").addEventListener("input", function () { ruleFilters.search = $("paiRuleSearch").value.trim().toLowerCase(); renderRules(); });
        $("paiRuleReset").addEventListener("click", function () {
            Object.keys(ruleFilters).forEach(function (key) { ruleFilters[key] = ""; });
            $("paiRuleSearch").value = "";
            renderRules();
        });
        $("paiRuleCollapseAll").addEventListener("click", function () { ruleGroups.setAll(visibleCategories, !ruleGroups.allCollapsed(visibleCategories)); });
        ruleGroups.bind($("paiRuleList"));
        EntraOpsFilters.bindPills($("paiRuleFacets"), ruleFilters, renderRules);
        $("paiRuleStats").addEventListener("click", function (ev) {
            var tile = ev.target.closest ? ev.target.closest("[data-rule-stat]") : null;
            if (!tile) return;
            if (tile.getAttribute("data-rule-stat") === "__exceptions") { $("secPaiExceptions").scrollIntoView({ behavior: "smooth", block: "start" }); return; }
            ruleFilters.status = tile.getAttribute("data-rule-stat");
            renderRules();
            $("secPaiRules").scrollIntoView({ behavior: "smooth", block: "start" });
        });
        $("paiRuleList").addEventListener("click", function (ev) {
            if (ev.target.closest && ev.target.closest("[data-group-toggle]")) return;
            // A click anywhere on the row opens the check (the title is the keyboard target).
            var row = ev.target.closest ? ev.target.closest("tr[data-rule]") : null;
            if (row && !ev.target.closest("[data-rule-open]")) openRuleBlade(row.getAttribute("data-rule"), "replace");
        });
        $("paiRuleBody").addEventListener("input", function (ev) {
            var acceptForm = ev.target.closest ? ev.target.closest("form.pai-accept-form") : null;
            if (acceptForm) { acceptForm.querySelector(".pai-accept-error").textContent = ""; return; }
            if (ev.target.id !== "paiRuleResultSearch") return;
            ruleBlade.search = ev.target.value.trim().toLowerCase();
            renderRuleResults();
        });
        $("paiRuleBody").addEventListener("change", function (ev) {
            var acceptForm = ev.target.closest ? ev.target.closest("form.pai-accept-form") : null;
            if (acceptForm) { if (ev.target.name === "State") updateAcceptState(acceptForm); return; }
            var rule = ruleById[ruleBlade.ruleId];
            var selectId = ev.target.getAttribute("data-select-result"), groupKey = ev.target.getAttribute("data-select-group");
            if (rule && (selectId || groupKey)) {
                // A finding, or all selectable findings of an object group.
                var targets = selectId ? [selectId] : ruleResultGroups(rule).groups.filter(function (group) { return group.key === groupKey; }).reduce(function (list, group) {
                    return list.concat(group.results.filter(function (result) { return resultSelectable(rule, result); }).map(resultId));
                }, []);
                targets.forEach(function (id) { if (ev.target.checked) ruleBlade.selected[id] = true; else delete ruleBlade.selected[id]; });
                renderRuleResults();
                return;
            }
            if (ev.target.id === "paiRuleShowUnclassified") ruleBlade.showUnclassified = ev.target.checked;
            else if (ev.target.id === "paiRuleShowAccepted") ruleBlade.showAccepted = ev.target.checked;
            else return;
            ruleBlade.showAll = false;
            renderRuleResults();
        });
        $("paiRuleBody").addEventListener("submit", function (ev) {
            if (ev.target.id !== "paiAcceptForm" && ev.target.id !== "paiBulkAcceptForm") return;
            ev.preventDefault();
            submitAcceptForm(ev.target);
        });
        $("paiRuleBody").addEventListener("click", function (ev) {
            var accept = ev.target.closest ? ev.target.closest("[data-accept]") : null;
            if (accept) {
                ruleBlade.acceptFor = accept.getAttribute("data-accept");
                renderRuleResults();
                if ($("paiAcceptForm")) { updateAcceptState($("paiAcceptForm")); $("paiAcceptForm").elements.Justification.focus(); }
                return;
            }
            var cancel = ev.target.closest ? ev.target.closest("[data-accept-cancel]") : null;
            if (cancel) {
                if (cancel.closest("#paiBulkAcceptForm")) ruleBlade.bulkOpen = false; else ruleBlade.acceptFor = "";
                renderRuleResults();
                return;
            }
            var toggle = ev.target.closest ? ev.target.closest("[data-result-group-toggle]") : null;
            if (toggle) {
                var key = toggle.getAttribute("data-result-group-toggle");
                ruleBlade.expanded[key] = !ruleBlade.expanded[key];
                renderRuleResults();
                var again = Array.from(document.querySelectorAll("[data-result-group-toggle]")).filter(function (element) { return element.getAttribute("data-result-group-toggle") === key; })[0];
                if (again) again.focus();
                return;
            }
            var rule = ruleById[ruleBlade.ruleId];
            if (!rule) return;
            if (ev.target.closest && ev.target.closest("[data-bulk-select-all]")) {
                // The results of the shown objects that can get an exception (all of them after "Show all").
                var groups = ruleResultGroups(rule).groups;
                (ruleBlade.showAll ? groups : groups.slice(0, MAX_RULE_GROUPS)).forEach(function (group) {
                    group.results.forEach(function (result) { if (resultSelectable(rule, result)) ruleBlade.selected[resultId(result)] = true; });
                });
                renderRuleResults();
                return;
            }
            if (ev.target.closest && ev.target.closest("[data-bulk-clear]")) { ruleBlade.selected = Object.create(null); ruleBlade.bulkOpen = false; renderRuleResults(); return; }
            if (ev.target.closest && ev.target.closest("[data-bulk-accept]")) {
                ruleBlade.bulkOpen = true;
                renderRuleResults();
                if ($("paiBulkAcceptForm")) $("paiBulkAcceptForm").elements.Justification.focus();
            }
        });
        $("paiExceptionExport").addEventListener("click", exportExceptions);
        // The file changed under the pending changes: keep them (based on the current file now) or discard them.
        $("paiExceptionFileChangedKeep").addEventListener("click", function () {
            if (heldExceptionChanges) applyExceptionChanges(heldExceptionChanges);
            heldExceptionChanges = null;
            exceptionFileChanged = false;
            exceptionsChanged();
        });
        $("paiExceptionFileChangedDiscard").addEventListener("click", discardExceptionChanges);
        $("paiExceptionImport").addEventListener("change", function () { importExceptions($("paiExceptionImport").files[0]); $("paiExceptionImport").value = ""; });
        $("paiExceptionReset").addEventListener("click", discardExceptionChanges);
        $("paiRuleBody").addEventListener("click", function (ev) {
            if (!ev.target.closest || !ev.target.closest("[data-rule-all]")) return;
            ruleBlade.showAll = true;
            renderRuleResults();
        });
        $("paiRuleClose").addEventListener("click", function () { closeRuleBlade(true); });
        $("paiRuleBackdrop").addEventListener("click", function () { closeRuleBlade(true); });
    }

    function onReady(fn) {
        if (document.readyState !== "loading") fn();
        else document.addEventListener("DOMContentLoaded", fn);
    }

    onReady(function () {
        var nav = $("nav");
        if ($("navToggle") && nav) $("navToggle").addEventListener("click", function () { nav.classList.toggle("open"); });
        document.querySelectorAll(".nav-item.section-item").forEach(function (item) {
            item.addEventListener("click", function () {
                var target = document.getElementById(item.getAttribute("data-target"));
                var viewHost = target && target.closest("[data-view]");
                if (viewHost && $("paiViewCrumb")) setView(viewHost.getAttribute("data-view"), true);
                if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
                if (nav) nav.classList.remove("open");
            });
            item.addEventListener("keydown", function (ev) {
                if (ev.key !== "Enter" && ev.key !== " ") return;
                ev.preventDefault();
                item.click();
            });
        });

        setView(viewFromUrl(), false);
        if (!DATA || !Array.isArray(DATA.objects)) return;
        $("paiEmptyState").classList.add("hidden");
        $("paiContent").classList.remove("hidden");
        if (DATA.tenantName) $("tenantName").textContent = DATA.tenantName;

        objects = DATA.objects.map(function (object) {
            object.objectId = String(object.objectId).toLowerCase();
            object.displayName = object.displayName || object.objectId;
            object.assignmentSummary = object.assignmentSummary || { total: 0, eligible: 0, active: 0, byTier: {}, bySystem: {}, highestTierName: "Unclassified" };
            return object;
        });
        objects.forEach(function (object) { objectsById[object.objectId] = object; });
        attachSavedFindings();
        loadExceptions();
        related = DATA.relatedObjects || {};
        if (FILE_ENABLED) {
            (SETTINGS.objectClassificationFile.entries || []).forEach(function (raw) {
                var entry = sanitizeEntry(raw);
                if (entry.ok) fileEntries[entry.value.objectId] = entry.value;
            });
        }
        document.querySelectorAll("[data-classification-method]:not([data-view])").forEach(function (element) {
            element.classList.toggle("hidden", !methodAllows(element));
        });
        state.worklistEntries = loadWorklist();

        initFilters();
        refreshFindings();
        buildRules();
        renderRuleStats();
        renderRuleSource();
        renderDataGaps();
        renderExceptions();
        $("paiAddTier").innerHTML = $("paiBulkTier").innerHTML;
        $("paiObjectOptions").innerHTML = objects.map(function (object) {
            return '<option value="' + esc(object.displayName + " (" + object.objectId + ")") + '">' + esc(typeLabel(object.objectType)) + "</option>";
        }).join("");
        wire();
        setView(viewFromUrl(), false);
        renderAll();
        applyUrl();
    });
})();
