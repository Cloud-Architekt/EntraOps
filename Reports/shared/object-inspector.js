(function () {
    "use strict";

    // A page that resolves #object= links itself (Configuration Analyzer opens the resource) loads this script with
    // data-object-deep-link="page": the inspector then neither opens nor writes #object= drawers on that page.
    var currentScript = document.currentScript;
    var pageOwnsObjectLinks = !!(currentScript && currentScript.getAttribute("data-object-deep-link") === "page");

    function esc(value) {
        return String(value == null ? "" : value).replace(/[&<>'"]/g, function (character) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" }[character];
        });
    }

    function values(items) {
        return Array.isArray(items) ? items.filter(function (item) { return item != null && item !== ""; }) : [];
    }

    function ensureDrawer() {
        if (document.getElementById("objectInspector")) return;
        document.body.insertAdjacentHTML("beforeend", '<div id="objectInspectorBackdrop" class="drawer-backdrop"></div><aside id="objectInspector" class="drawer" aria-label="Object details" aria-hidden="true"><div class="drawer-head"><div class="title" id="objectInspectorTitle"></div><button type="button" class="close" id="objectInspectorClose" aria-label="Close details">&times;</button></div><div class="drawer-body" id="objectInspectorBody"></div></aside>');
        document.getElementById("objectInspectorBackdrop").addEventListener("click", close);
        document.getElementById("objectInspectorClose").addEventListener("click", close);
        document.addEventListener("keydown", function (event) {
            if (event.key !== "Escape") return;
            var drawer = document.getElementById("objectInspector");
            if (drawer && drawer.classList.contains("open")) close();
        });
    }

    function close() {
        hide();
        // The deep link is cleared also when the page resolves #object= itself (Configuration Analyzer): otherwise the
        // next click on the same link would not change the hash, and the page would not open it again.
        if (/^#(object|config-object)=/.test(window.location.hash || "")) history.replaceState(null, "", window.location.pathname + window.location.search);
    }

    function hide() {
        var drawer = document.getElementById("objectInspector"), backdrop = document.getElementById("objectInspectorBackdrop");
        if (!drawer || !backdrop) return;
        drawer.classList.remove("open");
        backdrop.classList.remove("open");
        drawer.setAttribute("aria-hidden", "true");
    }

    function objectReferenceFromHash() {
        if (pageOwnsObjectLinks) return null;
        var match = /^#object=([^&]+)$/.exec(window.location.hash || "");
        if (!match) return null;
        try { return decodeURIComponent(match[1]); } catch (error) { return null; }
    }

    function objectDeepLink(reference) {
        return "#object=" + encodeURIComponent(reference);
    }

    function findObject(reference) {
        if (!reference || !window.EAM_DATA || !Array.isArray(window.EAM_DATA.objects)) return null;
        var wanted = String(reference).toUpperCase();
        return window.EAM_DATA.objects.filter(function (object) {
            return [object.objectId, object.objectDisplayName, object.objectUserPrincipalName].some(function (candidate) {
                return candidate && String(candidate).toUpperCase() === wanted;
            });
        })[0] || null;
    }

    function canonicalReference(reference) {
        var object = findObject(reference);
        if (object && object.objectId) return object.objectId;
        var data = window.ENTRAOPS_CONFIGANALYZER_DATA;
        if (!reference || !data || !data.blobs) return null;
        var wanted = String(reference).toUpperCase();
        var group = Object.keys(data.blobs).map(function (key) { return data.blobs[key]; }).filter(function (blob) {
            var properties = blob && blob.properties;
            if (!properties || String(blob.resourceType || "").toLowerCase() !== "microsoft.entra.group") return false;
            return [properties.Id, properties.DisplayName].some(function (value) { return value && String(value).toUpperCase() === wanted; });
        })[0];
        return group && group.properties && group.properties.Id ? group.properties.Id : null;
    }

    function resolvedGroupTierIndex() {
        // Merge the resolved group tiers of the Access Package Flow enrichment dataset (whose
        // own pages carry a richer group set, keyed by group id with members[] of all members)
        // with the Configuration Analyzer dataset. When both resolve the same group, the
        // Configuration Analyzer entry wins - it carries the tierNames[] breakdown and the
        // privileged-only members[] the inspector renders; AP-only groups are kept as fallback.
        var merged = {};
        var assignmentData = window.ENTRAOPS_ACCESSPACKAGE_ASSIGNMENTS;
        var assignmentTiers = assignmentData && assignmentData.resolvedGroupTiers;
        if (assignmentTiers && typeof assignmentTiers === "object") {
            Object.keys(assignmentTiers).forEach(function (id) { if (assignmentTiers[id]) merged[id] = assignmentTiers[id]; });
        }
        var analyzerData = window.ENTRAOPS_CONFIGANALYZER_DATA;
        var analyzerTiers = analyzerData && analyzerData.resolvedGroupTiers;
        if (analyzerTiers && typeof analyzerTiers === "object") {
            Object.keys(analyzerTiers).forEach(function (id) { if (analyzerTiers[id]) merged[id] = analyzerTiers[id]; });
        }
        return merged;
    }

    function groupRelationships(reference) {
        var data = window.ENTRAOPS_CONFIGANALYZER_DATA;
        if (!reference) return { owners: [], members: [] };
        var wanted = String(reference).toUpperCase();
        var group = data && data.blobs ? Object.keys(data.blobs).map(function (key) { return data.blobs[key]; }).filter(function (blob) {
            var properties = blob && blob.properties;
            if (!properties || String(blob.resourceType || "").toLowerCase() !== "microsoft.entra.group") return false;
            return [properties.Id, properties.DisplayName].some(function (value) { return value && String(value).toUpperCase() === wanted; });
        })[0] : null;
        function describe(items) {
            var entries = values(items);
            var described = entries.slice(0, 50).map(function (item) {
                var identity = typeof item === "object" ? (item.id || item.Id || item.displayName) : item;
                var object = findObject(identity);
                var tier = object ? (object.objectAdminTierLevelName || "Unclassified") : "UserAccess (not listed in PrivilegedEAM)";
                var name = typeof item === "object" ? (item.displayName || item.id || item.Id) : item;
                var itemTier = typeof item === "object" && item.tierName ? item.tierName : tier;
                return esc(name) + " <span class=\"muted\">(" + esc(itemTier) + ")</span>";
            });
            if (entries.length > 50) described.push('<span class="muted">Showing first 50 of ' + entries.length + " entries</span>");
            return described;
        }
        if (group && group.properties) return { owners: describe(group.properties.Owners), members: describe(group.properties.Members) };
        var resolved = resolvedGroupTierIndex();
        var wantedEntry = Object.keys(resolved).map(function (id) { return resolved[id]; }).filter(function (entry) {
            return entry && [entry.displayName, entry.id].some(function (value) { return value && String(value).toUpperCase() === wanted; });
        })[0] || resolved[reference] || resolved[String(reference).toLowerCase()] || resolved[String(reference).toUpperCase()];
        return { owners: [], members: describe(wantedEntry && wantedEntry.members) };
    }

    // Lazily-built module-level index over ENTRAOPS_CONFIGANALYZER_DATA. The dataset is static
    // after load, but snapshotRelationships previously deep-walked EVERY blob's property tree
    // and rebuilt resourcesByHash on each drawer open - a noticeable freeze on large datasets.
    // The inverted string index makes each open a handful of Map lookups instead.
    var __inspectorSnapshotIndex = null;
    function inspectorSnapshotIndex(data) {
        if (__inspectorSnapshotIndex) return __inspectorSnapshotIndex;
        var resourcesByHash = {};
        (data.snapshots || []).forEach(function (snapshot, snapshotIndex) {
            if (!snapshot.hasDetail) return;
            (snapshot.resources || []).forEach(function (resource) {
                resourcesByHash[resource.h] = { path: resource.p, snapshotIndex: snapshotIndex };
            });
        });
        var groupBlobProperties = [];
        var stringIndex = new Map();
        var hashOrder = {};
        var sequence = 0;
        Object.keys(data.blobs).forEach(function (hash, order) {
            hashOrder[hash] = order;
            var blob = data.blobs[hash], properties = blob && blob.properties;
            if (!properties) return;
            if (String(blob.resourceType || "").toLowerCase() === "microsoft.entra.group") groupBlobProperties.push(properties);
            (function walk(value, path) {
                if (typeof value === "string") {
                    var key = value.toUpperCase();
                    var list = stringIndex.get(key);
                    if (!list) { list = []; stringIndex.set(key, list); }
                    list.push({ hash: hash, path: path, seq: sequence++ });
                    return;
                }
                if (Array.isArray(value)) { value.forEach(function (item, index) { walk(item, path + "[" + index + "]"); }); return; }
                if (value && typeof value === "object") Object.keys(value).forEach(function (key) { walk(value[key], path ? path + "." + key : key); });
            })(properties, "");
        });
        __inspectorSnapshotIndex = { resourcesByHash: resourcesByHash, groupBlobProperties: groupBlobProperties, stringIndex: stringIndex, hashOrder: hashOrder };
        return __inspectorSnapshotIndex;
    }

    function snapshotRelationships(reference) {
        var data = window.ENTRAOPS_CONFIGANALYZER_DATA;
        if (!reference || !data || !data.blobs) return [];
        var index = inspectorSnapshotIndex(data);
        var aliases = new Set([String(reference).toUpperCase()]);
        var object = findObject(reference);
        [object && object.objectId, object && object.objectDisplayName, object && object.objectUserPrincipalName].filter(Boolean).forEach(function (value) { aliases.add(String(value).toUpperCase()); });
        // Same single-pass alias expansion over group blobs as before (blob order preserved).
        index.groupBlobProperties.forEach(function (properties) {
            if ([properties.Id, properties.DisplayName].some(function (value) { return value && aliases.has(String(value).toUpperCase()); })) {
                [properties.Id, properties.DisplayName].filter(Boolean).forEach(function (value) { aliases.add(String(value).toUpperCase()); });
            }
        });
        var resourcesByHash = index.resourcesByHash;
        var matchesByHash = {};
        aliases.forEach(function (alias) {
            var entries = index.stringIndex.get(alias);
            if (!entries) return;
            entries.forEach(function (entry) {
                (matchesByHash[entry.hash] = matchesByHash[entry.hash] || []).push(entry);
            });
        });
        var relationships = [];
        Object.keys(matchesByHash).sort(function (a, b) { return index.hashOrder[a] - index.hashOrder[b]; }).forEach(function (hash) {
            var blob = data.blobs[hash], properties = blob && blob.properties;
            if (!properties) return;
            // Sort by walk sequence so the path list matches the previous depth-first order.
            var matches = matchesByHash[hash].sort(function (a, b) { return a.seq - b.seq; }).map(function (entry) { return entry.path; });
            var isSelf = [properties.Id, properties.id].some(function (value) { return value && aliases.has(String(value).toUpperCase()); });
            if (!matches.length || isSelf) return;
            var resourceReference = resourcesByHash[hash];
            var label = (properties.DisplayName || properties.Name || (resourceReference && resourceReference.path) || blob.resourceType || "Snapshot resource") +
                " (" + (blob.resourceType || "resource") + ") - " + matches.slice(0, 4).join(", ");
            var resourceType = String(blob.resourceType || "").toLowerCase();
            var href = null;
            if (resourceType === "microsoft.entra.conditionalaccesspolicy" && properties.Id) {
                href = EntraOpsReportUtils.flowDeepLink(properties.Id, "../ConditionalAccessAnalysis/index.html");
            } else if (resourceType === "microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy" && properties.Id) {
                href = EntraOpsReportUtils.flowDeepLink(properties.Id, "../AccessPackageFlow/index.html");
            } else if (resourceType === "microsoft.entra.rolesetting" && properties.Id) {
                var path = matches.some(function (match) { return /^EligibleAssignment/i.test(match); }) ? "eligibleAssignment" :
                    (matches.some(function (match) { return /^Active/i.test(match); }) ? "activeAssignment" : "activation");
                href = EntraOpsReportUtils.flowDeepLink(properties.Id + "|" + path, "../PimRequestFlow/index.html");
            } else if (resourceReference) {
                href = "../ConfigurationAnalyzer/index.html?view=privileged#config-object=" + resourceReference.snapshotIndex + "|" + encodeURIComponent(resourceReference.path);
            }
            relationships.push(href ? { label: label, href: href } : label);
        });
        var deduplicated = relationships.filter(function (item, index, items) {
            var key = typeof item === "object" ? item.label + "|" + item.href : item;
            return items.findIndex(function (candidate) {
                return (typeof candidate === "object" ? candidate.label + "|" + candidate.href : candidate) === key;
            }) === index;
        });
        if (deduplicated.length <= 50) return deduplicated;
        var truncatedRelationships = deduplicated.slice(0, 50);
        truncatedRelationships.push("Showing first 50 of " + deduplicated.length + " related resources");
        return truncatedRelationships;
    }

    function tierBadge(tier) {
        if (!tier) return "";
        // Class-based so each dashboard's stylesheet (and its dark-theme overrides) colors the
        // badge - inline hex would defeat theming. All consuming dashboards define
        // .tier-badge.tier-{controlplane,managementplane,workloadplane,useraccess,unclassified}.
        var tiers = {
            ControlPlane: { label: "Control Plane", className: "tier-controlplane" },
            ManagementPlane: { label: "Management Plane", className: "tier-managementplane" },
            WorkloadPlane: { label: "Workload Plane", className: "tier-workloadplane" },
            UserAccess: { label: "User Access", className: "tier-useraccess" }
        };
        var meta = tiers[tier] || { label: tier, className: "tier-unclassified" };
        return ' <span class="tier-badge ' + meta.className + '">' + esc(meta.label) + "</span>";
    }

    function list(title, items) {
        var entries = values(items);
        if (!entries.length) return "";
        return "<h3>" + esc(title) + "</h3><ul class=\"drawer-list\">" + entries.map(function (entry) { return "<li>" + entry + "</li>"; }).join("") + "</ul>";
    }

    function relationshipList(title, items) {
        var entries = values(items);
        if (!entries.length) return "";
        return "<h3>" + esc(title) + "</h3><ul class=\"drawer-list\">" + entries.map(function (entry) {
            if (entry && typeof entry === "object") return '<li><a href="' + esc(entry.href) + '">' + esc(entry.label) + "</a></li>";
            return "<li>" + esc(entry) + "</li>";
        }).join("") + "</ul>";
    }

    function fieldSections(fields) {
        var sections = {};
        fields.forEach(function (field) {
            var section = field.section || "General";
            if (!sections[section]) sections[section] = [];
            sections[section].push(field);
        });
        return Object.keys(sections).map(function (section) {
            var rows = sections[section].map(function (field) { return "<dt>" + esc(field.label) + "</dt><dd>" + esc(field.value) + "</dd>"; }).join("");
            return '<details class="drawer-section" open><summary>' + esc(section) + '</summary><dl class="kv">' + rows + "</dl></details>";
        }).join("");
    }

    function htmlSections(sections) {
        return values(sections).filter(function (section) { return section && section.html; }).map(function (section) {
            return '<details class="drawer-section" open><summary>' + esc(section.title || "Details") + '</summary>' + section.html + "</details>";
        }).join("");
    }

    function roleRows(object, roleReference) {
        var assignments = object ? values(object.roleAssignments) :
            (roleReference && window.EAM_DATA && Array.isArray(window.EAM_DATA.objects) ? window.EAM_DATA.objects.flatMap(function (item) {
                return values(item.roleAssignments).map(function (assignment) {
                    return Object.assign({ objectId: item.objectId, objectDisplayName: item.objectDisplayName || item.objectId }, assignment);
                });
            }) : []);
        var matching = assignments.filter(function (assignment) {
            if (!roleReference) return true;
            var wanted = String(roleReference).toUpperCase();
            return [assignment.roleDefinitionId, assignment.roleDefinitionName].some(function (value) { return value && String(value).toUpperCase() === wanted; });
        });
        var rows = matching.slice(0, 30).map(function (assignment) {
            var classificationsByTier = Object.create(null);
            values(assignment.classification).forEach(function (classification) {
                var tier = classification.adminTierLevelName || "Unclassified";
                if (!classificationsByTier[tier]) classificationsByTier[tier] = [];
                if (classification.service && classificationsByTier[tier].indexOf(classification.service) === -1) classificationsByTier[tier].push(classification.service);
            });
            var tierOrder = ["ControlPlane", "ManagementPlane", "UserAccess", "Unclassified"];
            var classifications = Object.keys(classificationsByTier).sort(function (left, right) {
                var leftIndex = tierOrder.indexOf(left), rightIndex = tierOrder.indexOf(right);
                return (leftIndex < 0 ? tierOrder.length : leftIndex) - (rightIndex < 0 ? tierOrder.length : rightIndex);
            }).map(function (tier) {
                var tierLabel = { ControlPlane: "Control Plane", ManagementPlane: "Management Plane", UserAccess: "User Access" }[tier] || tier;
                return '<div class="role-classification-group"><span class="role-classification-tier">' + esc(tierLabel) + '</span><span class="role-classification-services">' + classificationsByTier[tier].map(esc).join("<br>") + "</span></div>";
            }).join("");
            var assignmentReference = assignment.roleAssignmentInstanceId || assignment.roleAssignmentId;
            var assetReference = assignment.objectId || (object && object.objectId);
            var eamHref = assignmentReference ? "../EamDashboard/index.html#assignment=" + encodeURIComponent(assignmentReference) :
                (assetReference ? "../EamDashboard/index.html#asset=" + encodeURIComponent(assetReference) : "");
            var scope = assignment.roleAssignmentScopeName || assignment.roleAssignmentScopeId || assignment.roleScope;
            var assignmentPath = [assignment.roleAssignmentType, assignment.roleAssignmentSubType].filter(Boolean).join(" - ");
            var metadata = [];
            if (scope) metadata.push('<span class="chip scope">Scope: ' + esc(scope) + "</span>");
            if (assignmentPath) metadata.push('<span class="chip brand">' + esc(assignmentPath) + "</span>");
            if (assignment.pimAssignmentType) metadata.push('<span class="chip">PIM: ' + esc(assignment.pimAssignmentType) + "</span>");
            if (assignment.eligibilityBy && assignment.eligibilityBy !== "N/A") metadata.push('<span class="chip">Via ' + esc(assignment.eligibilityBy) + "</span>");
            var detail = assignment.transitiveByObjectDisplayName ? '<div class="role-assignment-via">Through ' + esc(assignment.transitiveByObjectDisplayName) + "</div>" : "";
            return '<div class="role-assignment-head"><strong>' + esc(assignment.roleDefinitionName || assignment.roleDefinitionId || "Role assignment") + "</strong>" +
                (eamHref ? '<a class="role-assignment-link" href="' + esc(eamHref) + '">Open in EAM Dashboard &rarr;</a>' : "") + "</div>" +
                (assignment.objectDisplayName ? '<div class="role-assignment-via">Assigned to ' + esc(assignment.objectDisplayName) + "</div>" : "") +
                (metadata.length ? '<div class="role-assignment-meta">' + metadata.join("") + "</div>" : "") + detail +
                (classifications ? '<div class="role-assignment-classifications">' + classifications + "</div>" : "");
        });
        if (matching.length > 30) rows.push('<span class="muted">Showing first 30 of ' + matching.length + " role assignments</span>");
        return rows;
    }

    function open(options) {
        ensureDrawer();
        options = options || {};
        var object = findObject(options.reference);
        var relationships = groupRelationships(options.reference);
        var fields = values(options.fields).filter(function (field) { return field && field.value != null && field.value !== ""; });
        if (object) {
            fields.unshift({ label: "Object ID", value: object.objectId }, { label: "Object type", value: object.objectType }, { label: "Classification", value: object.objectAdminTierLevelName || "Unclassified" });
        } else if (options.tier) {
            fields.unshift({ label: "Classification", value: options.fallbackUserAccess && options.tier === "UserAccess" ? "UserAccess (not listed in PrivilegedEAM)" : options.tier });
        }
        var classifications = object ? values(object.classification).map(function (classification) {
            return esc(classification.adminTierLevelName || "Unclassified") + (classification.service ? " - " + esc(classification.service) : "");
        }) : [];
        var related = values(options.related).concat(snapshotRelationships(options.reference)).filter(function (item, index, items) {
            var key = typeof item === "object" ? item.label + "|" + item.href : item;
            return items.findIndex(function (candidate) {
                return (typeof candidate === "object" ? candidate.label + "|" + candidate.href : candidate) === key;
            }) === index;
        });
        var body = (values(options.tags).length ? "<p>" + values(options.tags).map(function (tag) { return '<span class="chip brand">' + esc(tag) + "</span>"; }).join(" ") + "</p>" : "") +
            fieldSections(fields) +
            htmlSections(options.htmlSections) +
            list("Classification", classifications) +
            list("Role assignments", roleRows(object, options.roleReference)) +
            list("Group owners", relationships.owners) +
            list("Group members", relationships.members) +
            list("API permissions", values(options.apiPermissions).map(esc)) +
            relationshipList("Related policies and paths", related);
        document.getElementById("objectInspectorTitle").innerHTML = esc(options.title || "Details") + tierBadge(object ? object.objectAdminTierLevelName : options.tier);
        document.getElementById("objectInspectorBody").innerHTML = body || '<p class="muted">No additional context is available for this item in the loaded report data.</p>';
        document.getElementById("objectInspector").classList.add("open");
        document.getElementById("objectInspectorBackdrop").classList.add("open");
        document.getElementById("objectInspector").setAttribute("aria-hidden", "false");
        if (options.urlReference && options.updateUrl && !pageOwnsObjectLinks) history.pushState(null, "", objectDeepLink(options.urlReference));
    }

    function openReference(reference) {
        var object = findObject(reference);
        open({
            title: object ? (object.objectDisplayName || object.objectId) : reference,
            reference: reference,
            updateUrl: false,
            fields: object ? [] : [{ label: "Object reference", value: reference }]
        });
    }

    function applyObjectDeepLink() {
        var reference = objectReferenceFromHash();
        if (reference) openReference(reference);
        else hide();
    }

    window.EntraOpsObjectInspector = {
        open: open,
        close: close,
        openReference: openReference,
        canonicalReference: canonicalReference,
        deepLink: objectDeepLink,
        applyDeepLink: applyObjectDeepLink
    };
    if (pageOwnsObjectLinks) return;
    window.addEventListener("hashchange", applyObjectDeepLink);
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", applyObjectDeepLink);
    else applyObjectDeepLink();
})();
