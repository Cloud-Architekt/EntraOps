/*
 * EntraOps Privileged Assets
 *
 * Object-centric view of privileged objects from window.ENTRAOPS_PRIVILEGED_ASSETS_DATA
 * (New-EntraOpsPrivilegedAssetsData) with two views: Overview (metrics and inventory) and Object
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
    var TIER_LEVEL = { ControlPlane: 0, ManagementPlane: 1, WorkloadPlane: 1, UserAccess: 2, Unclassified: 2 };
    var TIER_TAG = { ControlPlane: "0", ManagementPlane: "1", WorkloadPlane: "1", UserAccess: "2" };
    var TIER_ORDER = { ControlPlane: 0, ManagementPlane: 1, WorkloadPlane: 2, UserAccess: 3, Unclassified: 4 };
    var OBJECT_TYPES = ["user", "group", "serviceprincipal", "application"];
    var TYPE_LABEL = { user: "User", group: "Group", serviceprincipal: "Service principal", application: "Application" };
    var GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
    var CSA_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
    var STORE_KEY = "entraops.privilegedAssets.objectClassification.v1";
    var VIEWS = { overview: "Overview", classification: "Object Classification" };
    var PAGE_SIZE = 100;
    var MAX_IMPORT_BYTES = 5 * 1024 * 1024;
    var MAX_IMPORT_ROWS = 20000;

    var FINDINGS = [
        { id: "tierBreach", label: "Object tier below role assignments", severity: "high", help: "The object tier is less privileged than the most privileged classification of its role assignments (tier breach)." },
        { id: "unclassified", label: "Unclassified object", severity: "medium", help: "No object tier is defined by custom security attributes, the Object Classification File or Alternate Tier Level Attributes." },
        { id: "ownerLowerTier", label: "Owner with lower tier", severity: "high", help: "An owner is less privileged than the object it owns. Owners can manage the object (e.g. add credentials) and inherit its privileges." },
        { id: "ownsHigherTier", label: "Owns higher-tier object", severity: "high", help: "The object owns another privileged object with a more privileged tier." },
        { id: "parentLowerTier", label: "Identity parent with lower tier", severity: "medium", help: "The identity parent (agent identity blueprint or agent identity) is less privileged than this object." },
        { id: "sponsorMissing", label: "No sponsor", severity: "medium", help: "Agent identities and agent users should have an accountable sponsor." },
        { id: "deviceNotPaw", label: "Owns non-PAW devices", severity: "medium", help: "A Control or Management Plane user owns devices that are not the associated privileged access workstation." },
        { id: "pawMissing", label: "No associated PAW", severity: "info", help: "A Control Plane user has no associated privileged access workstation." },
        { id: "workAccountMissing", label: "No associated work account", severity: "info", help: "A Control or Management Plane member user is not linked to a regular work account." },
        { id: "hybridPrivileged", label: "Synchronized Control Plane identity", severity: "high", help: "A Control Plane object is synchronized from Active Directory and can be managed on-premises." },
        { id: "restrictedManagementGap", label: "Restricted management not applied", severity: "medium", help: "A Control or Management Plane user or group is not protected by restricted management (role, role-assignable group or restricted management AU)." },
        { id: "foreign", label: "Outside home tenant", severity: "info", help: "The object belongs to another tenant (guest, multi-tenant app or Tenant Governance delegation)." }
    ];
    var FINDING_BY_ID = {};
    FINDINGS.forEach(function (finding) { FINDING_BY_ID[finding.id] = finding; });
    var RELATIONSHIP_FINDINGS = ["ownerLowerTier", "ownsHigherTier", "parentLowerTier"];

    var state = {
        search: "", type: "", subType: "", tier: "", assignmentTier: "", au: "", restricted: "", sync: "", finding: "", worklist: "",
        whatIf: false, sort: "tier", sortDir: 1, page: 0, selected: new Set(), worklistEntries: {}, script: ""
    };
    var objects = [];
    var objectsById = {};
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
        var name = TIER_LABEL[tier] ? tier : "Unclassified";
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

    function loadWorklist() {
        var stored = null;
        try { stored = JSON.parse(localStorage.getItem(STORE_KEY) || "null"); } catch (_) { stored = null; }
        if (stored && stored.tenant === (DATA.tenantName || "") && stored.entries && typeof stored.entries === "object") {
            var entries = {};
            Object.keys(stored.entries).forEach(function (id) {
                var entry = sanitizeEntry(stored.entries[id]);
                if (entry.ok) entries[entry.value.objectId] = entry.value;
            });
            return entries;
        }
        return JSON.parse(JSON.stringify(fileEntries));
    }

    function saveWorklist() {
        try {
            localStorage.setItem(STORE_KEY, JSON.stringify({ tenant: DATA.tenantName || "", entries: state.worklistEntries }));
        } catch (_) { /* Local storage can be unavailable in hardened browsers. */ }
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
    function effectiveTier(object) {
        if (state.whatIf && state.worklistEntries[object.objectId]) return state.worklistEntries[object.objectId].adminTierLevelName;
        return TIER_LABEL[object.tierName] ? object.tierName : "Unclassified";
    }

    function requiredLevel(object) {
        var own = effectiveTier(object);
        var ownLevel = own === "Unclassified" ? 2 : TIER_LEVEL[own];
        var assignmentLevel = TIER_LEVEL[object.assignmentSummary.highestTierName];
        return Math.min(ownLevel, assignmentLevel === undefined ? 2 : assignmentLevel);
    }

    function relatedLevel(id) {
        var info = relatedInfo(id);
        return info.inInventory && info.tierName && info.tierName !== "Unclassified" ? TIER_LEVEL[info.tierName] : 2;
    }

    function computeFindings(object) {
        var found = [];
        var tier = effectiveTier(object);
        var objectLevel = tier === "Unclassified" ? 2 : TIER_LEVEL[tier];
        var highest = object.assignmentSummary.highestTierName;
        var assignmentLevel = highest === "Unclassified" ? null : TIER_LEVEL[highest];
        var needed = requiredLevel(object);
        var subType = String(object.objectSubType || "").toLowerCase();

        if (assignmentLevel !== null && objectLevel > assignmentLevel) found.push("tierBreach");
        if (tier === "Unclassified") found.push("unclassified");
        if ((object.owners || []).some(function (id) { return relatedLevel(id) > needed; })) found.push("ownerLowerTier");
        if ((object.ownedObjects || []).some(function (id) {
            var owned = objectsById[String(id).toLowerCase()];
            return owned && requiredLevel(owned) < needed;
        })) found.push("ownsHigherTier");
        if (object.identityParent && relatedLevel(object.identityParent) > needed) found.push("parentLowerTier");
        if (subType.indexOf("agent") === 0 && subType !== "agentidentityblueprint" && !(object.sponsors || []).length) found.push("sponsorMissing");
        if (object.objectType === "user" && needed <= 1) {
            var paw = (object.associatedPawDevice || []).map(function (id) { return String(id).toLowerCase(); });
            if ((object.ownedDevices || []).some(function (id) { return paw.indexOf(String(id).toLowerCase()) < 0; })) found.push("deviceNotPaw");
            if (needed === 0 && !paw.length) found.push("pawMissing");
            if (subType === "member" && !(object.associatedWorkAccount || []).length) found.push("workAccountMissing");
        }
        if (object.onPremSynchronized && needed === 0) found.push("hybridPrivileged");
        if ((object.objectType === "user" || object.objectType === "group") && needed <= 1 && (object.restrictedManagement === "Not applied" || object.restrictedManagement === "Conflict")) found.push("restrictedManagementGap");
        if (object.isForeign) found.push("foreign");
        return found;
    }

    // ---- Filters, sorting, rendering ---------------------------------------------------------------
    function fillSelect(id, options, allLabel) {
        var select = $(id);
        select.innerHTML = '<option value="">' + esc(allLabel || "All") + "</option>" + options.map(function (option) {
            return '<option value="' + esc(option.value) + '">' + esc(option.label) + "</option>";
        }).join("");
    }

    function initFilters() {
        var subTypes = {}, units = {};
        objects.forEach(function (object) {
            if (object.objectSubType) subTypes[object.objectSubType] = true;
            (object.administrativeUnits || []).forEach(function (unit) { units[unit.id] = unit.displayName || unit.id; });
        });
        fillSelect("paiFilterType", OBJECT_TYPES.filter(function (type) { return objects.some(function (o) { return o.objectType === type; }); }).map(function (type) { return { value: type, label: TYPE_LABEL[type] }; }));
        fillSelect("paiFilterSubType", Object.keys(subTypes).sort().map(function (subType) { return { value: subType, label: subType }; }));
        var tierOptions = TIERS.concat(["Unclassified"]).map(function (tier) { return { value: tier, label: TIER_LABEL[tier] }; });
        fillSelect("paiFilterTier", tierOptions);
        fillSelect("paiFilterAssignmentTier", tierOptions);
        fillSelect("paiFilterAu", [{ value: "__none", label: "No administrative unit" }].concat(Object.keys(units).sort(function (a, b) { return units[a].localeCompare(units[b]); }).map(function (id) { return { value: id, label: units[id] }; })));
        fillSelect("paiFilterRestricted", ["Applied", "Not applied", "Conflict", "Not available"].map(function (value) { return { value: value, label: value }; }));
        fillSelect("paiFilterSync", [{ value: "cloud", label: "Cloud-only" }, { value: "hybrid", label: "Synchronized (hybrid)" }]);
        fillSelect("paiFilterFinding", [{ value: "__any", label: "Any finding" }, { value: "__relationship", label: "Any relationship finding" }].concat(FINDINGS.map(function (finding) { return { value: finding.id, label: finding.label }; })));
        fillSelect("paiFilterWorklist", [{ value: "in", label: "In worklist" }, { value: "pending", label: "Pending changes" }, { value: "out", label: "Not in worklist" }]);
        $("paiBulkTier").innerHTML = TIERS.map(function (tier) { return '<option value="' + tier + '">' + esc(TIER_LABEL[tier]) + "</option>"; }).join("");
    }

    function matches(object) {
        if (state.search) {
            var haystack = [object.displayName, object.userPrincipalName, object.objectId].join(" ").toLowerCase();
            if (haystack.indexOf(state.search) < 0) return false;
        }
        if (state.type && object.objectType !== state.type) return false;
        if (state.subType && object.objectSubType !== state.subType) return false;
        if (state.tier && effectiveTier(object) !== state.tier) return false;
        if (state.assignmentTier && object.assignmentSummary.highestTierName !== state.assignmentTier) return false;
        if (state.au === "__none" && (object.administrativeUnits || []).length) return false;
        if (state.au && state.au !== "__none" && !(object.administrativeUnits || []).some(function (unit) { return unit.id === state.au; })) return false;
        if (state.restricted && object.restrictedManagement !== state.restricted) return false;
        if (state.sync === "hybrid" && !object.onPremSynchronized) return false;
        if (state.sync === "cloud" && object.onPremSynchronized) return false;
        if (state.finding === "__any" && !object._findings.length) return false;
        if (state.finding === "__relationship" && !object._findings.some(function (id) { return RELATIONSHIP_FINDINGS.indexOf(id) >= 0; })) return false;
        if (state.finding && state.finding.indexOf("__") !== 0 && object._findings.indexOf(state.finding) < 0) return false;
        if (state.worklist === "in" && !state.worklistEntries[object.objectId]) return false;
        if (state.worklist === "out" && state.worklistEntries[object.objectId]) return false;
        if (state.worklist === "pending" && ["Added", "Changed", "Removed"].indexOf(worklistStatus(object.objectId)) < 0) return false;
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
            case "findings": return -object._findings.length;
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
        objects.forEach(function (object) { object._findings = computeFindings(object); });
    }

    function renderStats() {
        var counts = { total: objects.length, breach: 0, unclassified: 0, relationship: 0 };
        objects.forEach(function (object) {
            if (object._findings.indexOf("tierBreach") >= 0) counts.breach++;
            if (object._findings.indexOf("unclassified") >= 0) counts.unclassified++;
            if (object._findings.some(function (id) { return RELATIONSHIP_FINDINGS.indexOf(id) >= 0; })) counts.relationship++;
        });
        var pending = pendingChanges();
        var tiles = [
            { label: "Privileged objects", value: counts.total, sub: TIERS.map(function (tier) { return TIER_LABEL[tier] + ": " + objects.filter(function (o) { return effectiveTier(o) === tier; }).length; }).join(" · "), filter: {} },
            { label: "Object tier below role assignments", value: counts.breach, sub: "Tier breaches by object tier", filter: { finding: "tierBreach" } },
            { label: "Relationship findings", value: counts.relationship, sub: "Owner, owned object or identity parent with a lower tier", filter: { finding: "__relationship" } },
            { label: "Object Classification worklist", value: Object.keys(state.worklistEntries).length, sub: pending.Added + " added · " + pending.Changed + " changed · " + pending.Removed + " removed", view: "classification" }
        ];
        $("paiStats").innerHTML = tiles.map(function (tile, index) {
            return '<button class="stat stat-action" type="button" data-stat="' + index + '"><div class="stat-accent"></div><div class="stat-label">' + esc(tile.label) + '</div><div class="stat-value">' + esc(tile.value) + '</div><div class="stat-sub">' + esc(tile.sub) + "</div></button>";
        }).join("");
        $("paiStats").querySelectorAll("[data-stat]").forEach(function (button) {
            button.addEventListener("click", function () {
                var tile = tiles[Number(button.getAttribute("data-stat"))];
                if (tile.view) { setView(tile.view, true); return; }
                resetFilters(false);
                Object.keys(tile.filter).forEach(function (key) { state[key] = tile.filter[key]; });
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

    function findingChips(ids) {
        return ids.map(function (id) {
            var finding = FINDING_BY_ID[id];
            return '<span class="chip pai-finding sev-' + finding.severity + '" title="' + esc(finding.help) + '">' + esc(finding.label) + "</span>";
        }).join(" ");
    }

    function renderInventory() {
        var list = filteredObjects();
        var pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
        if (state.page >= pages) state.page = pages - 1;
        var pageItems = list.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
        $("paiResultCount").textContent = list.length + " of " + objects.length + " objects";
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
                '<td><button type="button" class="pai-link" data-open="' + esc(object.objectId) + '">' + esc(object.displayName) + '</button><div class="muted pai-small cell-truncate" title="' + esc(object.userPrincipalName || object.objectId) + '">' + esc(object.userPrincipalName || object.objectId) + "</div></td>" +
                "<td>" + esc(TYPE_LABEL[object.objectType] || object.objectType) + '<div class="muted pai-small">' + breakable(object.objectSubType, true) + "</div></td>" +
                "<td>" + tierBadge(tier) + target + (status && status !== "Unchanged" ? ' <span class="status-chip ' + (status === "Added" ? "added" : status === "Removed" ? "removed" : "modified") + '">' + esc(status) + "</span>" : "") + "</td>" +
                "<td>" + assignmentCell(object) + "</td>" +
                "<td>" + relationshipCell(object) + "</td>" +
                "<td>" + (units ? '<div class="pai-units">' + units + "</div>" : '<span class="muted">None</span>') + "</td>" +
                "<td>" + (findingChips(object._findings) || '<span class="muted">None</span>') + "</td></tr>";
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
                "<td>" + esc(TYPE_LABEL[entry.objectType] || entry.objectType || "-") + (object && object.objectSubType ? '<div class="muted pai-small">' + esc(object.objectSubType) + "</div>" : "") + "</td>" +
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
                return "<li>" + esc(object.displayName) + " - " + esc(TYPE_LABEL[object.objectType] || object.objectType) + ", tenant " + esc(object.objectTenantId || "unknown") + "</li>";
            }).join("") + "</ul>" : "";
    }

    // Worklist changes the script would make on objects of other tenants, which can't be modified from the home tenant.
    function crossTenantScriptObjects() {
        return Object.keys(state.worklistEntries).sort().map(function (id) { return objectsById[id]; }).filter(function (object) {
            return object && object.isForeign && object.objectType !== "group" &&
                state.worklistEntries[object.objectId].adminTierLevelName !== (TIER_LABEL[object.tierName] ? object.tierName : "Unclassified");
        });
    }

    function renderAll() {
        refreshFindings();
        renderStats();
        renderInventory();
        renderWorklist();
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

    function setView(view, push) {
        if (!VIEWS[view]) view = "overview";
        document.querySelectorAll("[data-view]").forEach(function (element) { element.hidden = element.getAttribute("data-view") !== view || !methodAllows(element); });
        document.querySelectorAll("[data-view-nav]").forEach(function (item) { item.classList.toggle("active", item.getAttribute("data-view-nav") === view); });
        $("paiViewCrumb").textContent = VIEWS[view];
        $("paiViewTitle").textContent = view === "overview" ? "Privileged Assets" : "Object Classification";
        if (push && view !== viewFromUrl()) history.pushState(null, "", location.pathname + (view === "overview" ? "" : "?view=" + view));
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

    function openDrawer(id, updateUrl) {
        var object = objectsById[String(id || "").toLowerCase()];
        if (!object) return;
        var entry = state.worklistEntries[object.objectId], file = fileEntries[object.objectId];
        var tier = TIER_LABEL[object.tierName] ? object.tierName : "Unclassified";
        var kv = function (label, value) { return value === "" || value == null ? "" : "<dt>" + esc(label) + "</dt><dd>" + value + "</dd>"; };
        var identity = kv("Object ID", '<span class="cell-mono">' + esc(object.objectId) + "</span>") +
            kv("Type", esc(TYPE_LABEL[object.objectType] || object.objectType) + (object.objectSubType ? " · " + esc(object.objectSubType) : "")) +
            kv(object.objectType === "user" ? "User principal name" : "App id / sign-in name", esc(object.userPrincipalName)) +
            kv("Tenant", esc(object.objectTenantId) + (object.isForeign ? ' <span class="chip warn">Outside home tenant</span>' : "")) +
            kv("Sync source", object.onPremSynchronized ? "Synchronized (hybrid)" : "Cloud-only") +
            kv("RBAC systems", esc((object.roleSystems || []).join(", "))) +
            kv("Restricted management", esc(object.restrictedManagement) + '<div class="muted pai-small">Directory role: ' + (object.restrictedManagementByAadRole ? "yes" : "no") + " · Role-assignable group: " + (object.restrictedManagementByRAG ? "yes" : "no") + " · RMAU: " + (object.restrictedManagementByRMAU ? "yes" : "no") + "</div>");
        var classification = kv("Object tier", tierBadge(tier) + (object.tierLevel ? ' <span class="muted">level ' + esc(object.tierLevel) + "</span>" : "")) +
            kv("Highest role assignment tier", tierBadge(object.assignmentSummary.highestTierName)) +
            kv("Assignments by tier", TIERS.concat(["Unclassified"]).filter(function (t) { return object.assignmentSummary.byTier[t]; }).map(function (t) { return esc(TIER_LABEL[t]) + ": " + object.assignmentSummary.byTier[t]; }).join(" · ") || "None") +
            kv("Object Classification File", file ? tierBadge(file.adminTierLevelName) + (file.justification ? '<div class="muted pai-small">' + esc(file.justification) + "</div>" : "") : '<span class="muted">No entry</span>') +
            kv("Worklist target", entry ? tierBadge(entry.adminTierLevelName) + ' <span class="status-chip">' + esc(worklistStatus(object.objectId)) + "</span>" : '<span class="muted">Not in worklist</span>');
        var findings = object._findings.map(function (fid) {
            var finding = FINDING_BY_ID[fid];
            return '<li><span class="chip pai-finding sev-' + finding.severity + '">' + esc(finding.label) + '</span><div class="muted pai-small">' + esc(finding.help) + "</div></li>";
        }).join("");
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
            (findings ? '<details class="drawer-section" open><summary>Findings (' + object._findings.length + ')</summary><ul class="drawer-list pai-related">' + findings + "</ul></details>" : "") +
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
        $("paiDrawer").classList.add("open");
        $("paiDrawerBackdrop").classList.add("open");
        $("paiDrawer").setAttribute("aria-hidden", "false");
        if (updateUrl) history.replaceState(null, "", "#asset=" + encodeURIComponent(object.objectId));
    }

    function closeDrawer() {
        $("paiDrawer").classList.remove("open");
        $("paiDrawerBackdrop").classList.remove("open");
        $("paiDrawer").setAttribute("aria-hidden", "true");
        if (/^#asset=/.test(location.hash || "")) history.replaceState(null, "", location.pathname + location.search);
    }

    function applyDeepLink() {
        var match = /^#asset=([^&]+)$/.exec(location.hash || "");
        if (!match) return;
        try { openDrawer(decodeURIComponent(match[1]), false); } catch (_) { /* malformed hash */ }
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
        var headers = ["ObjectId", "DisplayName", "UserPrincipalName", "ObjectType", "ObjectSubType", "ObjectTier", "TargetTier", "HighestAssignmentTier", "Assignments", "EligibleAssignments", "RoleSystems", "Owners", "Sponsors", "OwnedObjects", "OwnedDevices", "IdentityParent", "AdministrativeUnits", "RestrictedManagement", "SyncSource", "Findings"];
        var names = function (ids) { return (ids || []).map(function (id) { return relatedInfo(id).displayName; }).join("; "); };
        var rows = filteredObjects().map(function (object) {
            var entry = state.worklistEntries[object.objectId];
            return {
                ObjectId: object.objectId, DisplayName: object.displayName, UserPrincipalName: object.userPrincipalName, ObjectType: object.objectType, ObjectSubType: object.objectSubType,
                ObjectTier: object.tierName, TargetTier: entry ? entry.adminTierLevelName : "", HighestAssignmentTier: object.assignmentSummary.highestTierName,
                Assignments: object.assignmentSummary.total, EligibleAssignments: object.assignmentSummary.eligible, RoleSystems: (object.roleSystems || []).join("; "),
                Owners: names(object.owners), Sponsors: names(object.sponsors), OwnedObjects: names(object.ownedObjects), OwnedDevices: names(object.ownedDevices),
                IdentityParent: object.identityParent ? relatedInfo(object.identityParent).displayName : "",
                AdministrativeUnits: (object.administrativeUnits || []).map(function (unit) { return unit.displayName || unit.id; }).join("; "),
                RestrictedManagement: object.restrictedManagement, SyncSource: object.onPremSynchronized ? "Hybrid" : "Cloud-only",
                Findings: object._findings.map(function (id) { return FINDING_BY_ID[id].label; }).join("; ")
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
            if (object.isForeign) { skipped.push(safeName(name) + " (" + id + "): belongs to another tenant - custom security attributes can only be set on objects of the home tenant"); return; }
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
    var FILTER_CONTROLS = { paiFilterType: "type", paiFilterSubType: "subType", paiFilterTier: "tier", paiFilterAssignmentTier: "assignmentTier", paiFilterAu: "au", paiFilterRestricted: "restricted", paiFilterSync: "sync", paiFilterFinding: "finding", paiFilterWorklist: "worklist" };

    function syncFilterControls() {
        Object.keys(FILTER_CONTROLS).forEach(function (id) { $(id).value = state[FILTER_CONTROLS[id]]; });
        $("paiSearch").value = state.search;
        $("paiWhatIf").checked = state.whatIf;
    }

    function resetFilters(render) {
        Object.keys(FILTER_CONTROLS).forEach(function (id) { state[FILTER_CONTROLS[id]] = ""; });
        state.search = "";
        state.page = 0;
        if (render !== false) { syncFilterControls(); renderInventory(); }
    }

    function selectedIds() { return Array.from(state.selected); }

    function wire() {
        Object.keys(FILTER_CONTROLS).forEach(function (id) {
            $(id).addEventListener("change", function () { state[FILTER_CONTROLS[id]] = $(id).value; state.page = 0; renderInventory(); });
        });
        $("paiSearch").addEventListener("input", function () { state.search = $("paiSearch").value.trim().toLowerCase(); state.page = 0; renderInventory(); });
        $("paiWhatIf").addEventListener("change", function () { state.whatIf = $("paiWhatIf").checked; renderAll(); });
        $("paiResetFilters").addEventListener("click", function () { resetFilters(); });
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
            var opener = ev.target.closest ? ev.target.closest("[data-open]") : null;
            if (opener) { openDrawer(opener.getAttribute("data-open"), true); return; }
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
        window.addEventListener("popstate", function () { setView(viewFromUrl(), false); });

        $("paiImport").addEventListener("change", function () { importFile($("paiImport").files[0]); $("paiImport").value = ""; });
        $("paiExportCsv").addEventListener("click", function () {
            download(fileBaseName() + ".csv", "text/csv;charset=utf-8", toCsv(["ObjectId", "ObjectType", "ObjectDisplayName", "AdminTierLevelName", "Justification"], fileRows()));
        });
        $("paiExportFile").addEventListener("click", function () {
            download(fileBaseName() + ".json", "application/json;charset=utf-8", JSON.stringify(fileRows(), null, 2) + "\n");
        });
        $("paiResetWorklist").addEventListener("click", function () {
            if (!window.confirm("Discard all worklist changes in this browser and reload the entries from the repository file?")) return;
            state.worklistEntries = JSON.parse(JSON.stringify(fileEntries));
            try { localStorage.removeItem(STORE_KEY); } catch (_) { /* ignore */ }
            renderAll();
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

        $("paiDrawerClose").addEventListener("click", closeDrawer);
        $("paiDrawerBackdrop").addEventListener("click", closeDrawer);
        document.addEventListener("keydown", function (ev) { if (ev.key === "Escape" && $("paiDrawer").classList.contains("open")) closeDrawer(); });
        window.addEventListener("hashchange", applyDeepLink);
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
        $("paiAddTier").innerHTML = $("paiBulkTier").innerHTML;
        $("paiObjectOptions").innerHTML = objects.map(function (object) {
            return '<option value="' + esc(object.displayName + " (" + object.objectId + ")") + '">' + esc(TYPE_LABEL[object.objectType] || object.objectType) + "</option>";
        }).join("");
        wire();
        setView(viewFromUrl(), false);
        renderAll();
        applyDeepLink();
    });
})();
