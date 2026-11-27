/*
 * EntraOps Privileged Assets - finding rules for the What-if view
 *
 * The findings of the report are evaluated in PowerShell (Invoke-EntraOpsFindingEvaluation,
 * EntraOps/Private/Findings/Invoke-EntraOpsPrivilegedAssetsFindingRule.ps1) and embedded in the data
 * file (findings.byObject). This file mirrors these rules for the What-if view, which re-evaluates them
 * with the tiers of the unsaved worklist, and for data files generated without findings. Keep both in
 * sync: Tests/Findings/PrivilegedAssetsFindingParity.Tests.ps1 compares them. RULES are the catalog entries
 * of these rules for data files without a findings block.
 *
 * env: { objectsById: {id: object}, related: relatedObjects of the data, tierOverride: function (objectId) -> tierName or null }
 */
(function (root) {
    "use strict";

    // The catalog entries of the rules below (FindingRules.json, Area PrivilegedAssets), only used when the data
    // file has no findings block (older data files) and therefore carries no rule metadata.
    var RULES = [
        { key: "tierBreach", id: "EO.1002", title: "Object tier below role assignments", severity: "High", category: "TierBoundaries" },
        { key: "ownerLowerTier", id: "EO.1004", title: "Owner with lower tier", severity: "High", category: "TierBoundaries" },
        { key: "ownsHigherTier", id: "EO.1005", title: "Owns higher-tier object", severity: "High", category: "TierBoundaries" },
        { key: "parentLowerTier", id: "EO.1007", title: "Identity parent with lower tier", severity: "Medium", category: "TierBoundaries" },
        { key: "unclassified", id: "EO.2001", title: "Unclassified object", severity: "Medium", category: "Classification" },
        { key: "hybridPrivileged", id: "EO.4001", title: "Synchronized Control Plane identity", severity: "High", category: "AccountProtection" },
        { key: "restrictedManagementGap", id: "EO.4005", title: "Restricted management not applied", severity: "Medium", category: "AccountProtection" },
        { key: "deviceNotPaw", id: "EO.4007", title: "Owns non-PAW devices", severity: "Medium", category: "AccountProtection" },
        { key: "pawMissing", id: "EO.4008", title: "No associated PAW", severity: "Medium", category: "AccountProtection" },
        { key: "workAccountMissing", id: "EO.4009", title: "No associated work account", severity: "Low", category: "AccountProtection" },
        { key: "foreign", id: "EO.4010", title: "Role assignment of a principal managed by another tenant", severity: "Info", category: "AccountProtection" },
        { key: "sponsorMissing", id: "EO.5003", title: "No sponsor", severity: "Medium", category: "WorkloadIdentities" }
    ];

    // Admin tier level: lower is more privileged. Unclassified objects count as Tier 2.
    var TIER_LEVEL = { ControlPlane: 0, ManagementPlane: 1, WorkloadPlane: 1, UserAccess: 2, Unclassified: 2 };

    function has(map, key) { return Object.prototype.hasOwnProperty.call(map, key); }

    function effectiveTier(object, env) {
        var override = env.tierOverride ? env.tierOverride(object.objectId) : null;
        if (override) return override;
        return has(TIER_LEVEL, object.tierName) ? object.tierName : "Unclassified";
    }

    // The most privileged tier of the object's own access: its role assignments without delegated permissions
    // (highestAccessTierName), or of all role assignments for data of older versions (highestTierName). A delegated
    // permission acts within the rights of the signed-in user, so it is a tier of the role assignment, not of the object.
    function accessTier(object) {
        var summary = object.assignmentSummary || {};
        return has(summary, "highestAccessTierName") ? summary.highestAccessTierName : summary.highestTierName;
    }

    function requiredLevel(object, env) {
        var own = effectiveTier(object, env);
        var ownLevel = own === "Unclassified" ? 2 : TIER_LEVEL[own];
        var assignmentLevel = TIER_LEVEL[accessTier(object)];
        return Math.min(ownLevel, assignmentLevel === undefined ? 2 : assignmentLevel);
    }

    // The inventory object behind a related ID (an object ID, or the app ID of an identity parent).
    function inventoryObject(id, env) {
        var key = String(id || "").toLowerCase();
        if (env.objectsById[key]) return env.objectsById[key];
        var entry = env.related[key];
        return entry && entry.objectId && env.objectsById[entry.objectId] ? env.objectsById[entry.objectId] : null;
    }

    // Related objects outside the inventory, or unclassified, count as Tier 2.
    function relatedLevel(id, env) {
        var object = inventoryObject(id, env);
        var tier = object ? effectiveTier(object, env) : "";
        return tier && tier !== "Unclassified" ? TIER_LEVEL[tier] : 2;
    }

    // Users, and groups that are privileged by their classification only: a group with Control or Management Plane
    // access is reported by unprotectedPrivilegedGroup (EO.4004, a Privileged EAM rule).
    // EO.4004 reads highestAccessTierName only, so data without it keeps the group here.
    function restrictedManagementScope(object) {
        var access = (object.assignmentSummary || {}).highestAccessTierName;
        return object.objectType === "user" || (object.objectType === "group" && access !== "ControlPlane" && access !== "ManagementPlane");
    }

    function compute(object, env) {
        var found = [];
        var tier = effectiveTier(object, env);
        var objectLevel = tier === "Unclassified" ? 2 : TIER_LEVEL[tier];
        var highest = accessTier(object);
        var assignmentLevel = highest === "Unclassified" || !has(TIER_LEVEL, highest) ? null : TIER_LEVEL[highest];
        var needed = requiredLevel(object, env);
        var subType = String(object.objectSubType || "").toLowerCase();

        // Unclassified objects are reported by "unclassified" (EO.2001), not as a tier breach as well.
        if (assignmentLevel !== null && tier !== "Unclassified" && objectLevel > assignmentLevel) found.push("tierBreach");
        // Microsoft first-party service principals are operated by Microsoft, not classified by the tenant.
        if (tier === "Unclassified" && !object.isMicrosoftFirstParty) found.push("unclassified");
        if ((object.owners || []).some(function (id) { return relatedLevel(id, env) > needed; })) found.push("ownerLowerTier");
        if ((object.ownedObjects || []).some(function (id) {
            var owned = env.objectsById[String(id).toLowerCase()];
            return owned && requiredLevel(owned, env) < needed;
        })) found.push("ownsHigherTier");
        if (object.identityParent && relatedLevel(object.identityParent, env) > needed) found.push("parentLowerTier");
        // The tenant principal of a blueprint has no sponsors: they are kept on the blueprint (like the PowerShell rule).
        if (subType.indexOf("agent") === 0 && subType !== "agentidentityblueprint" && subType !== "agentidentityblueprintprincipal" && !(object.sponsors || []).length) found.push("sponsorMissing");
        if (object.objectType === "user" && needed <= 1) {
            var paw = (object.associatedPawDevice || []).map(function (id) { return String(id).toLowerCase(); });
            if ((object.ownedDevices || []).some(function (id) { return paw.indexOf(String(id).toLowerCase()) < 0; })) found.push("deviceNotPaw");
            // A user of another tenant has its PAW and work account in its home tenant (EO.4010/EO.4011 report it).
            if (needed === 0 && !paw.length && !object.isForeign) found.push("pawMissing");
            if (subType === "member" && !(object.associatedWorkAccount || []).length && !object.isForeign) found.push("workAccountMissing");
        }
        if (object.onPremSynchronized && needed === 0) found.push("hybridPrivileged");
        // "Conflict" (a role-assignable group in a restricted management administrative unit) is protected by the role-assignable group.
        // A group with Control or Management Plane access is reported by unprotectedPrivilegedGroup (EO.4004), not twice.
        if (restrictedManagementScope(object) && needed <= 1 && object.restrictedManagement === "Not applied") found.push("restrictedManagementGap");
        if (object.isForeign && !object.isMicrosoftFirstParty) found.push("foreign");
        return found;
    }

    // Whether the rule `key` evaluates the object: the scope of the rule (Applies of
    // Invoke-EntraOpsPrivilegedAssetsFindingRule.ps1), so the report can count the evaluated objects of a check.
    function applies(key, object, env) {
        var tier = effectiveTier(object, env);
        var highest = accessTier(object);
        var needed = requiredLevel(object, env);
        var subType = String(object.objectSubType || "").toLowerCase();
        var isUser = object.objectType === "user";
        switch (key) {
            case "tierBreach": return highest !== "Unclassified" && has(TIER_LEVEL, highest) && tier !== "Unclassified";
            case "unclassified": return !object.isMicrosoftFirstParty;
            case "ownerLowerTier": return (object.owners || []).length > 0;
            case "ownsHigherTier": return (object.ownedObjects || []).length > 0;
            case "parentLowerTier": return Boolean(object.identityParent);
            case "sponsorMissing": return subType.indexOf("agent") === 0 && subType !== "agentidentityblueprint" && subType !== "agentidentityblueprintprincipal";
            case "deviceNotPaw": return isUser && needed <= 1;
            case "pawMissing": return isUser && needed === 0 && !object.isForeign;
            case "workAccountMissing": return isUser && needed <= 1 && subType === "member" && !object.isForeign;
            case "hybridPrivileged": return needed === 0;
            case "restrictedManagementGap": return restrictedManagementScope(object) && needed <= 1;
            case "foreign": return !object.isMicrosoftFirstParty;
            default: return false;
        }
    }

    var api = { RULES: RULES, TIER_LEVEL: TIER_LEVEL, accessTier: accessTier, effectiveTier: effectiveTier, requiredLevel: requiredLevel, relatedLevel: relatedLevel, applies: applies, compute: compute };
    if (typeof module === "object" && module.exports) {
        module.exports = api;
    } else {
        root.EntraOpsPrivilegedAssetsFindings = api;
    }
})(typeof window !== "undefined" ? window : this);
