/*
 * EntraOps Access Path Map
 *
 * APM-style force-directed graph visualization of the EntraOps
 * OpenGraph model (the same node/edge kinds emitted by
 * Export-EntraOpsPrivilegedEAMBloodHound / the BloodHound integration),
 * enriched with classification, scope, device and identity-relationship
 * details, and cross-filterable the same way as the Tier Breach Analyzer.
 *
 * Data contract: window.ENTRAOPS_APM_DATA = {
 *   generatedFrom: [..], tenantId: "...",
 *   nodes: [{ id, kinds: [..], properties: {..} }],
 *   edges: [{ kind, source, target, properties: {..} }]
 * } written by New-EntraOpsAccessPathMapData.
 */
(function () {
    "use strict";

    const DATA = window.ENTRAOPS_APM_DATA;
    if (DATA && typeof DATA.tenantName === "string" && DATA.tenantName.trim()) {
        document.getElementById("tenantName").textContent = DATA.tenantName.trim();
    }
    if (window.EOReview) {
        EOReview.init({ app: "AccessPathMap", appLabel: "Access Path Map" });
    }
    if (!DATA || !Array.isArray(DATA.nodes)) {
        document.addEventListener("DOMContentLoaded", function () {
            const app = document.getElementById("app");
            const box = document.createElement("div");
            box.className = "error-box";
            box.innerHTML =
                "<strong>No dataset found.</strong><br>" +
                "Generate <code>data/access-path-map-data.js</code> from your EntraOps Privileged EAM export first:" +
                "<br><br><code>Import-Module ./EntraOps; New-EntraOpsAccessPathMapData</code>" +
                "<br><br>then reload this page.";
            const head = app.querySelector(".page-head");
            if (head) head.after(box);
            else app.appendChild(box);
        });
        return;
    }

    // ---- Enterprise Access Model palette ------------------------------------
    const TIER_ORDER = ["ControlPlane", "ManagementPlane", "WorkloadPlane", "UserAccess", "Unclassified"];
    const TIER_COLOR = {
        ControlPlane: "#e0555f",
        ManagementPlane: "#e0a23c",
        WorkloadPlane: "#4fa8e0",
        UserAccess: "#4caf6d",
        Unclassified: "#8a8f98",
    };
    const TIER_BADGE_CLASS = {
        ControlPlane: "tier-controlplane",
        ManagementPlane: "tier-managementplane",
        WorkloadPlane: "tier-workloadplane",
        UserAccess: "tier-useraccess",
        Unclassified: "tier-unclassified",
    };

    // ---- Node kind -> visual bucket (APM-style glyph nodes) ---------
    const BUCKETS = {
        user: { label: "Users", color: "#5aa9e6", glyph: "U", r: 15 },
        group: { label: "Groups", color: "#b280d1", glyph: "G", r: 15 },
        serviceprincipal: { label: "Service principals", color: "#e0a23c", glyph: "SP", r: 15 },
        device: { label: "Devices", color: "#5cc48c", glyph: "D", r: 13 },
        role: { label: "Roles", color: "#e28a63", glyph: "R", r: 12 },
        roleassignment: { label: "Role assignments", color: "#e06fa0", glyph: "RA", r: 11 },
        administrativeunit: { label: "Administrative units", color: "#9a86d6", glyph: "AU", r: 13 },
        tenant: { label: "Tenant", color: "#4fd1c5", glyph: "T", r: 18 },
        base: { label: "Other objects", color: "#8a8f98", glyph: "?", r: 11 },
    };
    const KIND_TO_BUCKET = {
        AZUser: "user",
        AZGroup: "group",
        AZServicePrincipal: "serviceprincipal",
        AZDevice: "device",
        AZRole: "role",
        EO_DefenderRole: "role",
        EO_IntuneRole: "role",
        EO_IdGovRole: "role",
        EO_AppRole: "role",
        EO_AzureRole: "role",
        EO_EntraRoleAssignment: "roleassignment",
        EO_DefenderRoleAssignment: "roleassignment",
        EO_IntuneRoleAssignment: "roleassignment",
        EO_IdGovRoleAssignment: "roleassignment",
        EO_AppRoleAssignment: "roleassignment",
        EO_AzureRoleAssignment: "roleassignment",
        EO_AdministrativeUnit: "administrativeunit",
        EO_Tenant: "tenant",
        EO_Base: "base",
    };

    // ---- Relationship kinds -> readable label (APM-style, no "EO" text) --
    const EDGE_LABELS = {
        EO_HasEntraRole: "HasRole",
        EO_HasDefenderRole: "HasRole",
        EO_HasIntuneRole: "HasRole",
        EO_HasIdGovRole: "HasRole",
        EO_HasAppRole: "HasRole",
        EO_HasAzureRole: "HasRole",
        EO_EligibleForEntraRole: "EligibleFor",
        EO_EligibleForDefenderRole: "EligibleFor",
        EO_EligibleForIntuneRole: "EligibleFor",
        EO_EligibleForIdGovRole: "EligibleFor",
        EO_EligibleForAppRole: "EligibleFor",
        EO_EligibleForAzureRole: "EligibleFor",
        EO_HasEntraRoleAssignment: "HasAssignment",
        EO_HasDefenderRoleAssignment: "HasAssignment",
        EO_HasIntuneRoleAssignment: "HasAssignment",
        EO_HasIdGovRoleAssignment: "HasAssignment",
        EO_HasAppRoleAssignment: "HasAssignment",
        EO_HasAzureRoleAssignment: "HasAssignment",
        EO_EntraRoleAssigned: "RoleAssigned",
        EO_DefenderRoleAssigned: "RoleAssigned",
        EO_IntuneRoleAssigned: "RoleAssigned",
        EO_IdGovRoleAssigned: "RoleAssigned",
        EO_AppRoleAssigned: "RoleAssigned",
        EO_AzureRoleAssigned: "RoleAssigned",
        EO_ClassifiedViaObject: "ClassifiedVia",
        EO_ScopedTo: "ScopedTo",
        EO_ScopedViaResource: "ScopedViaResource",
        EO_AssignedToAdministrativeUnit: "MemberOfAU",
        EO_HasWorkAccount: "HasWorkAccount",
        EO_UsesPAW: "UsesPAW",
        EO_PAWFor: "PAWFor",
        EO_OwnsDevice: "OwnsDevice",
        EO_DeviceOwner: "DeviceOwner",
        EO_OwnerOf: "OwnerOf",
        EO_OwnedBy: "OwnedBy",
        EO_IsSponsoredBy: "SponsoredBy",
        EO_HasIdentityParent: "IdentityParent",
        EO_IntuneRolePermission: "DeviceAction",
        AZMemberOf: "MemberOf",
    };
    function edgeLabel(kind) {
        return EDGE_LABELS[kind] || String(kind).replace(/^(EO_|AZ)/, "");
    }

    // Node/edge kind strings in the dataset carry internal EO_ / AzureHound-native AZ
    // prefixes (e.g. EO_EntraRoleAssignment, AZUser) so they match the BloodHound
    // OpenGraph model exactly - but those prefixes are pure implementation detail and
    // not shown anywhere in the UI, so there is no visible tie to BloodHound/AzureHound.
    function stripKindPrefix(kind) {
        return String(kind).replace(/^(EO_|AZ)/, "");
    }

    // ---- Relationship categories (filter checkboxes) ------------------------
    const EDGE_CATEGORY = {};
    [
        ["assignment", ["EO_HasEntraRole", "EO_HasDefenderRole", "EO_HasIntuneRole", "EO_HasIdGovRole", "EO_HasAppRole", "EO_HasAzureRole",
            "EO_EligibleForEntraRole", "EO_EligibleForDefenderRole", "EO_EligibleForIntuneRole", "EO_EligibleForIdGovRole", "EO_EligibleForAppRole", "EO_EligibleForAzureRole",
            "EO_HasEntraRoleAssignment", "EO_HasDefenderRoleAssignment", "EO_HasIntuneRoleAssignment", "EO_HasIdGovRoleAssignment", "EO_HasAppRoleAssignment", "EO_HasAzureRoleAssignment",
            "EO_EntraRoleAssigned", "EO_DefenderRoleAssigned", "EO_IntuneRoleAssigned", "EO_IdGovRoleAssigned", "EO_AppRoleAssigned", "EO_AzureRoleAssigned"]],
        ["classification", ["EO_ClassifiedViaObject", "EO_ScopedTo", "EO_ScopedViaResource", "EO_AssignedToAdministrativeUnit"]],
        ["device", ["EO_UsesPAW", "EO_PAWFor", "EO_OwnsDevice", "EO_DeviceOwner", "EO_IntuneRolePermission"]],
        ["ownership", ["EO_OwnerOf", "EO_OwnedBy"]],
        ["identity", ["EO_HasWorkAccount", "EO_IsSponsoredBy", "EO_HasIdentityParent", "AZMemberOf"]],
    ].forEach(([cat, kinds]) => kinds.forEach((k) => (EDGE_CATEGORY[k] = cat)));
    // Plain-text labels: buildChecks escapes them, so no pre-encoded entities here.
    const EDGE_CATEGORY_LABEL = {
        assignment: "Role assignments & eligibility",
        classification: "Classification & scope",
        device: "Devices & PAW",
        ownership: "Object ownership",
        identity: "Identity relationships",
    };
    function categoryOf(kind) {
        return EDGE_CATEGORY[kind] || "assignment";
    }

    // Edges that carry computed tier-breach flags (principal -> role / assignment).
    const BREACHABLE_PATTERN = /^EO_(Has|EligibleFor)\w*Role(Assignment)?$/;
    const ROLE_ASSIGNED_PATTERN = /^EO_\w*RoleAssigned$/;

    // Role node ids per role assignment node (EO_*RoleAssigned: role -> assignment).
    const rolesByAssignment = new Map();
    DATA.edges.forEach((e) => {
        if (!ROLE_ASSIGNED_PATTERN.test(e.kind)) return;
        if (!rolesByAssignment.has(e.target)) rolesByAssignment.set(e.target, new Set());
        rolesByAssignment.get(e.target).add(e.source);
    });

    // The same privilege is usually represented twice: principal -> role assignment and
    // principal -> role (linked via role -> assignment). Both edges stay in the graph, but
    // counts must include each principal -> privilege path once: the role assignment edge,
    // or the role edge when no (visible) assignment edge of that principal leads to an
    // assignment of that role. Computed from the graph structure (not only the generator's
    // "distinctpath" flag) so datasets generated before that flag existed count correctly
    // and filters hiding role assignment nodes fall back to the role edge.
    function distinctPathEdges(edges, base) {
        const viaAssignment = new Set();
        base.forEach((e) => {
            if (!BREACHABLE_PATTERN.test(e.kind) || !/RoleAssignment$/.test(e.kind)) return;
            (rolesByAssignment.get(e.target) || []).forEach((roleId) => viaAssignment.add(e.source + "|" + roleId));
        });
        const seen = new Set();
        return edges.filter((e) => {
            if (!/RoleAssignment$/.test(e.kind) && viaAssignment.has(e.source + "|" + e.target)) return false;
            const key = e.source + "|" + e.kind + "|" + e.target;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    // Role definition nodes (not role assignment nodes) reached by the given breach edges:
    // direct role edge targets plus the role(s) behind each reached role assignment.
    function rolesReached(edges) {
        const roles = new Set();
        edges.forEach((e) => {
            const tN = nodesById.get(e.target);
            if (tN && tN.bucket === "role") roles.add(e.target);
            else (rolesByAssignment.get(e.target) || []).forEach((roleId) => roles.add(roleId));
        });
        return roles;
    }

    // ---- Property display names (PascalCase) --------------------------------
    // Node/edge properties are stored all-lowercase in the dataset (OpenGraph convention -
    // see Export-EntraOpsPrivilegedEAMBloodHound / New-EntraOpsAccessPathMapData), so the
    // original word boundaries are lost. This is a display-only lookup - the dataset property
    // keys themselves are never touched (they must stay lowercase for BloodHound compatibility).
    const PROPERTY_LABELS = {
        name: "Name",
        displayname: "DisplayName",
        objectid: "ObjectId",
        objecttype: "ObjectType",
        objectsubtype: "ObjectSubType",
        userprincipalname: "UserPrincipalName",
        appid: "AppId",
        rbacsystem: "RbacSystem",
        rbacsystems: "RbacSystems",
        syncsource: "SyncSource",
        entraopsadmintierlevel: "EntraOpsAdminTierLevel",
        entraopsadmintierlevelname: "EntraOpsAdminTierLevelName",
        restrictedmanagementbyrag: "RestrictedManagementByRAG",
        restrictedmanagementbyaadrole: "RestrictedManagementByAadRole",
        restrictedmanagementbyrmau: "RestrictedManagementByRMAU",
        classification_tierlevels: "ClassificationTierLevels",
        classification_tiernames: "ClassificationTierNames",
        classification_services: "ClassificationServices",
        admintierlevel: "AdminTierLevel",
        admintierlevelname: "AdminTierLevelName",
        service: "Service",
        taggedby: "TaggedBy",
        taggedbyrolesystem: "TaggedByRoleSystem",
        resourcename: "ResourceName",
        resourceid: "ResourceId",
        eamtier: "EAMTier",
        resultingscope: "ResultingScope",
        reason: "Reason",
        roleassignmentid: "RoleAssignmentId",
        roleassignmenttype: "RoleAssignmentType",
        roleassignmentsubtype: "RoleAssignmentSubType",
        roleassignmentscopeid: "RoleAssignmentScopeId",
        roleassignmentscopename: "RoleAssignmentScopeName",
        roledefinitionid: "RoleDefinitionId",
        roledefinitionname: "RoleDefinitionName",
        roletype: "RoleType",
        isprivileged: "IsPrivileged",
        matchedactions: "MatchedActions",
        actions: "Actions",
        description: "Description",
        categories: "Categories",
        knownattackpaths: "KnownAttackPaths",
        knownattackpathnames: "KnownAttackPathNames",
        knownattackpathseverity: "KnownAttackPathSeverity",
        pimassignmenttype: "PIMAssignmentType",
        pimmanagedrole: "PIMManagedRole",
        principaltier: "PrincipalTier",
        servicetier: "ServiceTier",
        tierbreach: "TierBreach",
        tier0breach: "Tier0Breach",
        distinctpath: "DistinctPath",
        unresolved: "Unresolved",
    };
    // Fallback for any property not in the lookup above (e.g. a future dataset addition):
    // split on underscores and capitalize each segment. Concatenated-lowercase keys with no
    // delimiter can't be reliably word-split without a dictionary, so they just get their
    // first letter capitalized.
    function propLabel(key) {
        if (PROPERTY_LABELS[key]) return PROPERTY_LABELS[key];
        return String(key)
            .split("_")
            .filter(Boolean)
            .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
            .join("");
    }

    // ---- Build node index with computed display metadata --------------------
    const nodesById = new Map();
    DATA.nodes.forEach((n) => {
        const kinds = n.kinds || [];
        const bucketKey = kinds.map((k) => KIND_TO_BUCKET[k]).find((b) => b) || "base";
        const props = n.properties || {};
        const tierName =
            props.entraopsadmintierlevelname ||
            (Array.isArray(props.classification_tiernames) && props.classification_tiernames[0]) ||
            null;
        const label = props.displayname || props.name || n.id;
        nodesById.set(n.id, {
            id: n.id,
            kinds,
            bucket: bucketKey,
            props,
            label,
            tierName: tierName && TIER_COLOR[tierName] ? tierName : null,
            // Precomputed once here (not per filter pass) - search filtering runs over
            // every edge on every keystroke, and rebuilding+lowercasing this string per
            // call was the dominant cost of the search box at large-tenant scale.
            searchHay: (
                label +
                " " +
                (props.roledefinitionname || "") +
                " " +
                (props.roleassignmentscopename || "") +
                " " +
                (props.classification_services ? props.classification_services.join(" ") : "")
            ).toLowerCase(),
        });
    });

    // ---- Known (documented) attack paths --------------------------------------
    // A node participates in a *documented* attack path when New-EntraOpsAccessPathMapData
    // tagged it with knownattackpaths (matched against the Classification Explorer's curated
    // catalog). Zips the parallel id/name arrays into [{id, name}] for display + deep links.
    function nodeAttackPaths(n) {
        if (!n || !n.props || !Array.isArray(n.props.knownattackpaths)) return [];
        const names = n.props.knownattackpathnames || [];
        return n.props.knownattackpaths.map((id, i) => ({ id, name: names[i] || id }));
    }
    function edgeAttackPaths(e) {
        const sN = nodesById.get(typeof e.source === "object" ? e.source.id : e.source);
        const tN = nodesById.get(typeof e.target === "object" ? e.target.id : e.target);
        const byId = new Map();
        nodeAttackPaths(sN).concat(nodeAttackPaths(tN)).forEach((p) => byId.set(p.id, p));
        return Array.from(byId.values());
    }
    function attackPathLink(id) {
        return "../ClassificationExplorer/index.html#attackpaths/" + encodeURIComponent(id);
    }

    // Precomputed once at startup: nodes referenced by at least one documented attack
    // path. Avoids re-deriving (and allocating a Map for) each edge's attack-path list
    // on every render when the "Only documented attack paths" filter is active.
    const attackPathNodeIds = new Set();
    nodesById.forEach((n) => {
        if (nodeAttackPaths(n).length) attackPathNodeIds.add(n.id);
    });

    // ---- Scope siblings: other privileged objects sharing a role assignment scope -----
    // Role assignment nodes carry roleassignmentscopeid/roleassignmentscopename (the raw
    // RBAC scope, e.g. an Azure resource/management group or Entra directory scope) even
    // when that scope has no dedicated graph node (only Administrative Unit / tenant-root
    // scopes get an EO_ScopedTo edge to an actual node). Indexing by scope id surfaces "who
    // else is privileged on this same scope" regardless of whether a scope node exists.
    const assignmentPrincipal = new Map(); // roleAssignmentNodeId -> principal node id
    const scopeSiblingIndex = new Map(); // roleassignmentscopeid -> [roleAssignmentNodeId, ...]
    DATA.edges.forEach((e) => {
        if (edgeLabel(e.kind) === "HasAssignment") assignmentPrincipal.set(e.target, e.source);
    });
    nodesById.forEach((n) => {
        if (n.bucket !== "roleassignment") return;
        const scopeId = n.props.roleassignmentscopeid;
        if (!scopeId) return;
        if (!scopeSiblingIndex.has(scopeId)) scopeSiblingIndex.set(scopeId, []);
        scopeSiblingIndex.get(scopeId).push(n.id);
    });
    // Other privileged objects (via their role assignment) sharing this node's scope.
    function scopedSiblings(n) {
        if (n.bucket !== "roleassignment" || !n.props.roleassignmentscopeid) return [];
        const ids = scopeSiblingIndex.get(n.props.roleassignmentscopeid) || [];
        return ids
            .filter((id) => id !== n.id)
            .map((id) => nodesById.get(id))
            .filter(Boolean);
    }
    // Principals/objects reaching a scope-like node (AU/Tenant/classification object/hosting
    // resource) via EO_ScopedTo / EO_ClassifiedViaObject / EO_ScopedViaResource edges in the
    // *full* dataset (not the current view/filter), so scope context is always discoverable
    // regardless of active filters.
    function scopeRelatedPrincipals(nodeId) {
        const seen = new Map();
        DATA.edges.forEach((e) => {
            if (
                (e.kind === "EO_ScopedTo" || e.kind === "EO_ClassifiedViaObject" || e.kind === "EO_ScopedViaResource") &&
                e.target === nodeId
            ) {
                const sN = nodesById.get(e.source);
                if (sN && !seen.has(sN.id)) seen.set(sN.id, sN);
            }
        });
        return Array.from(seen.values());
    }

    // ---- Options for filters --------------------------------------------------
    const allSystems = Array.from(
        new Set(DATA.edges.map((e) => e.properties && e.properties.rbacsystem).filter(Boolean))
    ).sort();
    const allTypeBuckets = Array.from(
        new Set(Array.from(nodesById.values()).map((n) => n.bucket))
    ).filter((b) => BUCKETS[b]);
    allTypeBuckets.sort((a, b) => Object.keys(BUCKETS).indexOf(a) - Object.keys(BUCKETS).indexOf(b));
    // Canonical display order for the Relationships filter checkboxes. Always shown
    // (even when the current dataset has no edges of that category yet, e.g. a
    // tenant/export with no object-ownership relationships) so the filter option is
    // always discoverable rather than silently disappearing when a category happens
    // to be empty.
    const EDGE_CATEGORY_ORDER = ["assignment", "classification", "device", "ownership", "identity"];
    const allEdgeCategories = EDGE_CATEGORY_ORDER;

    // ---- State -----------------------------------------------------------------
    const state = {
        view: "tier0",
        systems: new Set(allSystems),
        types: new Set(allTypeBuckets),
        edgeCats: new Set(allEdgeCategories),
        search: "",
        focusNodeId: null,
        selectedPathKey: null,
        tier0RolesOnly: false,
        // Restricts every view (Tier 0 / All tier breach / Full graph) to only nodes/edges
        // that match a *documented* attack path from the Classification Explorer's curated
        // catalog (Reports/ClassificationExplorer/content/attack-paths/*.md) - i.e. a role or
        // role assignment tagged with knownattackpaths by New-EntraOpsAccessPathMapData. This
        // is distinct from "tier breach" (crossing an Enterprise Access Model tier boundary,
        // which the tier0/breach views already cover): a path can be a tier breach without
        // being a documented technique, and vice versa.
        knownAttackPathsOnly: false,
    };

    // Tracks which focused node (if any) should have its *complete* local neighborhood
    // expanded in the graph regardless of the active view/filter - set only via the node
    // drawer's "Show full context in graph" action (see openNodeDrawer), so a plain click
    // to inspect a node doesn't unexpectedly rebuild/re-zoom the graph. Naturally resets
    // whenever a different node becomes focused (it just won't match anymore).
    let expandFocusNodeId = null;

    let currentPaths = []; // last rendered attack-path table rows (for CSV + deep link)
    const PATH_DEFAULT_LIMIT = 150;
    let pathLimit = PATH_DEFAULT_LIMIT;
    const PATH_PAGE_STEP = 250;

    // Any search/filter change alters the result set, so paging restarts at the first
    // page - otherwise a prior "Show all" leaves pathLimit stuck at thousands of rows
    // and every keystroke re-renders all of them (see EamDashboard's resetPagination).
    function resetPathPaging() {
        pathLimit = PATH_DEFAULT_LIMIT;
    }
    let simulation = null;
    let nodeSel = null, linkSel = null, linkHitSel = null, labelSel = null;
    let zoomFitTimer = null; // pending auto-fit after drawGraph (one at a time)

    // ---- Build filter UI ---------------------------------------------------
    buildChecks("systemChecks", allSystems, state.systems, onFilterChange);
    buildChecks(
        "typeChecks",
        allTypeBuckets.map((b) => [b, BUCKETS[b].label]),
        state.types,
        onFilterChange
    );
    buildChecks(
        "edgeChecks",
        allEdgeCategories.map((c) => [c, EDGE_CATEGORY_LABEL[c] || c]),
        state.edgeCats,
        onFilterChange
    );

    function onFilterChange() {
        state.selectedPathKey = null;
        state.tier0RolesOnly = false;
        resetPathPaging();
        render();
    }

    function setView(view, tier0RolesOnly = false) {
        state.view = view;
        state.tier0RolesOnly = tier0RolesOnly;
        state.selectedPathKey = null;
        document.querySelectorAll(".nav-item.view-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
        resetPathPaging();
        render();
    }

    function buildChecks(hostId, options, set, onChange) {
        const el = document.getElementById(hostId);
        const opts = options.map((o) => (Array.isArray(o) ? o : [o, o]));
        el.innerHTML = opts
            .map(([v, lbl]) => `<label><input type="checkbox" data-v="${esc(v)}" checked/>${esc(lbl)}</label>`)
            .join("");
        el.querySelectorAll("input").forEach((cb) =>
            cb.addEventListener("change", (e) => {
                const v = e.target.dataset.v;
                if (e.target.checked) set.add(v);
                else set.delete(v);
                onChange();
            })
        );
    }

    let searchDebounce = null;
    document.getElementById("search").addEventListener("input", (e) => {
        state.search = e.target.value.trim().toLowerCase();
        // Debounced: a full render re-filters every edge, rebuilds the table and
        // restarts the force simulation - far too heavy per keystroke on large graphs.
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(onFilterChange, 180);
    });
    document.getElementById("attackPathsOnly").addEventListener("change", (e) => {
        state.knownAttackPathsOnly = e.target.checked;
        onFilterChange();
    });
    document.getElementById("exportCsv").addEventListener("click", exportCsv);
    document.getElementById("navToggle").addEventListener("click", () => {
        document.getElementById("nav").classList.toggle("open");
    });
    document.querySelectorAll(".nav-item.view-item").forEach((el) => {
        const activate = () => {
            setView(el.dataset.view);
            document.getElementById("nav").classList.remove("open");
        };
        el.addEventListener("click", activate);
        el.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" && e.key !== " ") return;
            e.preventDefault();
            activate();
        });
    });
    document.getElementById("clearFocus").addEventListener("click", () => {
        state.focusNodeId = null;
        const hadSelectedPath = state.selectedPathKey !== null;
        state.selectedPathKey = null;
        updateFocusChip();
        if (expandFocusNodeId || hadSelectedPath) {
            // Focus expansion changed the visible edge set - a full render is required.
            expandFocusNodeId = null;
            render();
        } else {
            // Pure highlight change: restyle the existing graph, no relayout.
            applyFocusStyles();
            if (lastRenderBase) renderPathTable(lastRenderBase);
        }
    });
    document.getElementById("zoomFit").addEventListener("click", zoomFit);
    document.getElementById("relayout").addEventListener("click", () => {
        if (simulation) simulation.alpha(1).restart();
    });

    // ---- Node label helpers --------------------------------------------------
    function nodeMatchesSearch(n) {
        if (!state.search) return true;
        return n.searchHay.includes(state.search);
    }

    function nodeTypeVisible(n) {
        return state.types.has(n.bucket);
    }

    // ---- Filtering -------------------------------------------------------------
    function edgeMatchesSearch(e, sN, tN) {
        // Inclusive on either side: searching for a principal's name should
        // still surface its relationships even when the role/target name
        // itself does not match the query (and vice versa).
        if (!state.search) return true;
        if (nodeMatchesSearch(sN) || nodeMatchesSearch(tN)) return true;
        if (e._searchHay === undefined) {
            const p = e.properties || {};
            e._searchHay = (
                (p.roleassignmentscopename || "") + " " + (p.service || "") + " " + (p.rbacsystem || "")
            ).toLowerCase();
        }
        return e._searchHay.includes(state.search);
    }

    function baseFilteredEdges() {
        return DATA.edges.filter((e) => {
            if (!state.edgeCats.has(categoryOf(e.kind))) return false;
            const sys = e.properties && e.properties.rbacsystem;
            if (sys && !state.systems.has(sys)) return false;
            const sN = nodesById.get(e.source);
            const tN = nodesById.get(e.target);
            if (!sN || !tN) return false;
            if (!nodeTypeVisible(sN) || !nodeTypeVisible(tN)) return false;
            if (!edgeMatchesSearch(e, sN, tN)) return false;
            return true;
        });
    }

    function viewFilteredEdges(base) {
        // "Tier 0 attack paths" / "All tier breach paths" narrow the graph to role
        // assignment/eligibility edges that cross a tier boundary - tier0breach/tierbreach
        // are only ever computed for that "assignment" edge category (see
        // New-EntraOpsAccessPathMapData's $BreachableEdgePattern). Context relationships
        // (ownership, identity/sponsor, device/PAW, classification & scope) never carry
        // those flags, so without this exemption their "Relationships" filter checkboxes
        // would be silently non-functional outside the "Full graph" view - Owners/OwnedBy/
        // Sponsors/IdentityParent/AssociatedWorkAccount/AssociatedPawDevice/etc. would never
        // render even when explicitly checked.
        let edges = base;
        if (state.view === "tier0") {
            edges = base.filter((e) => categoryOf(e.kind) !== "assignment" || (e.properties && e.properties.tier0breach));
        } else if (state.view === "breach") {
            edges = base.filter((e) => categoryOf(e.kind) !== "assignment" || (e.properties && e.properties.tierbreach));
        }
        if (!state.tier0RolesOnly) return edges;
        const tier0Roles = new Set(base
            .filter((e) => e.properties && e.properties.tier0breach)
            .map((e) => e.target));
        return edges.filter((e) => tier0Roles.has(e.source) || tier0Roles.has(e.target));
    }

    function attackPathEdges(base) {
        // "Known" attack paths: edges where the tier-breach computation applies
        // (principal -> role / role-assignment), matching the current view.
        const withFlags = base.filter((e) => e.properties && e.properties.tierbreach !== undefined);
        if (state.view === "tier0") return withFlags.filter((e) => e.properties.tier0breach);
        if (state.view === "breach") return withFlags.filter((e) => e.properties.tierbreach);
        return withFlags;
    }

    // ---- Graph build -----------------------------------------------------------
    const MAX_GRAPH_EDGES = 700;

    function buildGraph(base) {
        let edges = viewFilteredEdges(base);

        if (state.selectedPathKey) {
            edges = edges.filter((e) => edgeKey(e) === state.selectedPathKey);
        }

        let truncated = false;
        const totalBeforeCap = edges.length;
        if (edges.length > MAX_GRAPH_EDGES) {
            // Prioritize breach edges so the headline attack paths stay visible.
            edges = edges
                .slice()
                .sort((a, b) => Number((b.properties || {}).tier0breach) - Number((a.properties || {}).tier0breach) ||
                    Number((b.properties || {}).tierbreach) - Number((a.properties || {}).tierbreach))
                .slice(0, MAX_GRAPH_EDGES);
            truncated = true;
        }

        // A focused node reveals its *complete* local neighborhood - scope (EO_ScopedTo),
        // classification provenance (EO_ClassifiedViaObject), devices, sponsors, etc. - when
        // explicitly expanded (see the node drawer's "Show full context in graph" action),
        // even when those edges don't match the current view/filter. Otherwise this context
        // (e.g. "what scope is this tagged via, and who else shares it") would silently
        // disappear depending on which view happens to be selected.
        if (state.focusNodeId && state.focusNodeId === expandFocusNodeId) {
            const already = new Set(edges.map((e) => e.source + "|" + e.kind + "|" + e.target));
            base.forEach((e) => {
                if (e.source === state.focusNodeId || e.target === state.focusNodeId) {
                    const key = e.source + "|" + e.kind + "|" + e.target;
                    if (!already.has(key)) {
                        edges.push(e);
                        already.add(key);
                    }
                }
            });
        }

        const nodeIds = new Set();
        edges.forEach((e) => {
            nodeIds.add(e.source);
            nodeIds.add(e.target);
        });

        const nodes = Array.from(nodeIds)
            .map((id) => nodesById.get(id))
            .filter(Boolean)
            .map((n) => Object.assign({}, n));
        const links = edges.map((e) => ({
            source: e.source,
            target: e.target,
            kind: e.kind,
            properties: e.properties || {},
        }));

        return { nodes, links, truncated, totalEdges: totalBeforeCap };
    }

    // ---- Stats -------------------------------------------------------------
    function renderStats(base) {
        const principals = new Set();
        base.forEach((e) => {
            const sN = nodesById.get(e.source);
            if (sN && ["user", "group", "serviceprincipal"].includes(sN.bucket)) principals.add(sN.id);
        });
        const breachEdges = distinctPathEdges(base.filter((e) => e.properties && e.properties.tierbreach), base);
        const tier0Edges = distinctPathEdges(base.filter((e) => e.properties && e.properties.tier0breach), base);
        const tier0Roles = rolesReached(tier0Edges);

        const stats = [
            { num: nodesById.size, lbl: "Graph nodes (total)", view: "all" },
            { num: DATA.edges.length, lbl: "Graph edges (total)", view: "all" },
            { num: principals.size, lbl: "Principals in view" },
            {
                num: breachEdges.length, lbl: "Tier breach paths", danger: true, view: "breach",
                tip: "Distinct principal \u2192 role assignment paths where the principal's tier is less privileged than the service tier (each assignment counted once, not once per role and assignment edge)",
            },
            {
                num: tier0Edges.length, lbl: "Tier 0 attack paths", danger: true, view: "tier0",
                tip: "Distinct principal \u2192 role assignment paths from a Tier 1/2 principal to a Tier 0 (Control Plane) service (each assignment counted once, not once per role and assignment edge)",
            },
            {
                num: tier0Roles.size, lbl: "Roles reaching Tier 0", danger: true, view: "tier0", tier0RolesOnly: true,
                tip: "Distinct role definitions (not role assignments) held by a Tier 1/2 principal on a Tier 0 (Control Plane) service",
            },
        ];
        document.getElementById("stats").innerHTML = stats
            .map(
                (s) =>
                    `<div class="stat${s.view ? " stat-action" : ""}${s.view === state.view && !!s.tier0RolesOnly === state.tier0RolesOnly ? " active" : ""}"${s.tip ? ` title="${esc(s.tip)}"` : ""}${s.view ? ` data-view="${s.view}" data-tier0-roles="${!!s.tier0RolesOnly}" role="button" tabindex="0" aria-pressed="${s.view === state.view && !!s.tier0RolesOnly === state.tier0RolesOnly}"` : ""}><span class="stat-accent" style="background:${s.danger ? "var(--tier-control)" : "var(--brand)"
                    }"></span><div class="stat-label">${s.lbl}</div><div class="stat-value"${s.danger ? ' style="color:var(--tier-control)"' : ""
                    }>${s.num.toLocaleString()}</div></div>`
            )
            .join("");
    }

    document.getElementById("stats").addEventListener("click", (ev) => {
        const card = ev.target.closest("[data-view]");
        if (card) setView(card.dataset.view, card.dataset.tier0Roles === "true");
    });
    document.getElementById("stats").addEventListener("keydown", (ev) => {
        if (ev.key !== "Enter" && ev.key !== " ") return;
        const card = ev.target.closest("[data-view]");
        if (!card) return;
        ev.preventDefault();
        setView(card.dataset.view, card.dataset.tier0Roles === "true");
    });

    function updateViewCounts(base) {
        const set = (id, n) => {
            const el = document.getElementById(id);
            if (el) el.textContent = n.toLocaleString();
        };
        set("cnt-tier0", distinctPathEdges(base.filter((e) => e.properties && e.properties.tier0breach), base).length);
        set("cnt-breach", distinctPathEdges(base.filter((e) => e.properties && e.properties.tierbreach), base).length);
        set("cnt-all", base.length);
    }

    // ---- Legend ------------------------------------------------------------
    function renderLegend(nodes) {
        const present = new Set(nodes.map((n) => n.bucket));
        const items = Object.keys(BUCKETS)
            .filter((b) => present.has(b))
            .map((b) => `<div class="li"><span class="sw" style="background:${BUCKETS[b].color}"></span>${BUCKETS[b].label}</div>`);
        const tiers = TIER_ORDER.filter((t) => nodes.some((n) => n.tierName === t)).map(
            (t) => `<div class="li"><span class="sw" style="background:transparent;border:2px solid ${TIER_COLOR[t]}"></span>${t}</div>`
        );
        document.getElementById("legend").innerHTML = items.join("") + (tiers.length ? '<div style="border-top:1px solid #2a3242;margin:4px 0;"></div>' + tiers.join("") : "");
    }

    // ---- SVG / force-directed graph --------------------------------------------
    const svg = d3.select("#graph");
    const zoomLayer = svg.append("g").attr("class", "zoom-layer");
    const linkLayer = zoomLayer.append("g").attr("class", "links");
    const nodeLayer = zoomLayer.append("g").attr("class", "nodes");
    const tooltip = d3.select("#tooltip");

    svg.append("defs").html(
        '<marker id="arrow" viewBox="0 -5 10 10" refX="17" refY="0" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,-5L10,0L0,5" fill="#5a6376"></path></marker>' +
        '<marker id="arrow-breach" viewBox="0 -5 10 10" refX="17" refY="0" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,-5L10,0L0,5" fill="#e0555f"></path></marker>'
    );

    const zoomBehavior = d3
        .zoom()
        .scaleExtent([0.15, 3])
        .on("zoom", (ev) => zoomLayer.attr("transform", ev.transform));
    svg.call(zoomBehavior);
    svg.on("click", (ev) => {
        if (ev.target === svg.node()) {
            state.focusNodeId = null;
            updateFocusChip();
            applyFocusStyles();
        }
    });

    function zoomFit() {
        const bounds = nodeLayer.node().getBBox();
        if (!bounds.width || !bounds.height) return;
        const wrap = document.querySelector(".apm-canvas-wrap");
        const w = wrap.clientWidth, h = wrap.clientHeight || 640;
        const scale = Math.max(0.15, Math.min(2, 0.85 / Math.max(bounds.width / w, bounds.height / h)));
        const tx = w / 2 - scale * (bounds.x + bounds.width / 2);
        const ty = h / 2 - scale * (bounds.y + bounds.height / 2);
        svg.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    }

    function drawGraph(graph) {
        if (simulation) simulation.stop();

        const wrap = document.querySelector(".apm-canvas-wrap");
        const width = wrap.clientWidth || 960;
        const height = 640;
        svg.attr("viewBox", `0 0 ${width} ${height}`);

        const empty = document.getElementById("graphEmpty");
        if (graph.nodes.length === 0) {
            linkLayer.selectAll("*").remove();
            nodeLayer.selectAll("*").remove();
            empty.classList.remove("hidden");
            empty.textContent = "No graph data matches the current filters.";
            renderLegend([]);
            return;
        }
        empty.classList.add("hidden");
        renderLegend(graph.nodes);

        // Surface graph truncation (MAX_GRAPH_EDGES cap) so users in very large
        // environments know they are looking at a prioritized subset, not everything.
        const truncChip = document.getElementById("graphTruncated");
        if (graph.truncated) {
            truncChip.textContent =
                "Graph capped: " + graph.links.length.toLocaleString() + " of " +
                graph.totalEdges.toLocaleString() + " edges shown \u2013 refine filters";
            truncChip.classList.remove("hidden");
        } else {
            truncChip.classList.add("hidden");
        }

        linkSel = linkLayer
            .selectAll("g.apm-link")
            .data(graph.links, edgeKeyOf)
            .join((enter) => {
                const g = enter.append("g").attr("class", "apm-link");
                g.append("path").attr("class", "hit");
                g.append("path").attr("class", "line");
                g.append("text");
                return g;
            });

        linkSel
            .classed("breach", (d) => !!(d.properties && d.properties.tierbreach))
            .on("mousemove", (ev, d) => showTip(ev, edgeTooltip(d)))
            .on("mouseleave", hideTip)
            .on("click", (ev, d) => {
                ev.stopPropagation();
                openEdgeDrawer(d);
                setDeepLink(edgeHash(d));
            });

        linkSel
            .select("path.line")
            .attr("stroke", (d) => (d.properties && d.properties.tierbreach ? "#e0555f" : "#3a4356"))
            .attr("stroke-opacity", (d) => (d.properties && d.properties.tierbreach ? 0.85 : 0.55))
            .attr("marker-end", (d) => (d.properties && d.properties.tierbreach ? "url(#arrow-breach)" : "url(#arrow)"));

        linkSel.select("text").text((d) => edgeLabel(d.kind));

        nodeSel = nodeLayer
            .selectAll("g.apm-node")
            .data(graph.nodes, (d) => d.id)
            .join((enter) => {
                const g = enter.append("g").attr("class", "apm-node");
                g.append("circle").attr("class", "tier-ring");
                g.append("circle").attr("class", "body");
                g.append("text").attr("class", "glyph");
                g.append("text").attr("class", "label");
                return g;
            });

        nodeSel.select("circle.body")
            .attr("r", (d) => BUCKETS[d.bucket].r)
            .attr("fill", (d) => BUCKETS[d.bucket].color);
        nodeSel.select("circle.tier-ring")
            .attr("r", (d) => BUCKETS[d.bucket].r + 4)
            .attr("stroke", (d) => (d.tierName ? TIER_COLOR[d.tierName] : "transparent"));
        nodeSel.select("text.glyph").text((d) => BUCKETS[d.bucket].glyph);
        nodeSel.select("text.label")
            .attr("y", (d) => BUCKETS[d.bucket].r + 16)
            .text((d) => truncate(d.label, 22));

        nodeSel
            .on("mousemove", (ev, d) => showTip(ev, nodeTooltip(d)))
            .on("mouseleave", hideTip)
            .on("click", (ev, d) => {
                ev.stopPropagation();
                state.focusNodeId = d.id;
                updateFocusChip();
                applyFocusStyles();
                openNodeDrawer(d);
                setDeepLink(nodeHash(d));
            })
            .on("contextmenu", (ev, d) => showNodeContextMenu(ev, d));

        nodeSel.call(
            d3
                .drag()
                .on("start", (ev, d) => {
                    if (!ev.active) simulation.alphaTarget(0.25).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on("drag", (ev, d) => {
                    d.fx = ev.x;
                    d.fy = ev.y;
                })
                .on("end", (ev, d) => {
                    if (!ev.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                })
        );

        simulation = d3
            .forceSimulation(graph.nodes)
            .force("link", d3.forceLink(graph.links).id((d) => d.id).distance(95).strength(0.35))
            .force("charge", d3.forceManyBody().strength(-230))
            .force("collide", d3.forceCollide().radius((d) => BUCKETS[d.bucket].r + 18))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .on("tick", ticked);

        function ticked() {
            linkSel.select("path.line").attr("d", linkPath);
            linkSel.select("path.hit").attr("d", linkPath);
            linkSel.select("text").attr("transform", (d) => {
                const mx = (d.source.x + d.target.x) / 2;
                const my = (d.source.y + d.target.y) / 2;
                return `translate(${mx},${my})`;
            });
            nodeSel.attr("transform", (d) => `translate(${d.x},${d.y})`);
        }

        applyFocusStyles();
        // One pending auto-fit at a time: rapid re-renders (keystrokes) otherwise stack
        // timers and fire several competing zoom transitions.
        clearTimeout(zoomFitTimer);
        zoomFitTimer = setTimeout(zoomFit, 350);
    }

    // Stable identity for a link, both before the force simulation resolves
    // source/target ids into node objects (fresh links) and after (already-bound
    // links). Without this, every render recreated all link DOM elements because
    // old keys degraded to "[object Object]|...".
    function edgeKeyOf(d) {
        const s = typeof d.source === "object" ? d.source.id : d.source;
        const t = typeof d.target === "object" ? d.target.id : d.target;
        return s + "|" + d.kind + "|" + t;
    }

    function linkPath(d) {
        const dx = d.target.x - d.source.x;
        const dy = d.target.y - d.source.y;
        const dr = Math.hypot(dx, dy) * 1.4;
        if (!dr) return `M${d.source.x},${d.source.y}L${d.target.x},${d.target.y}`;
        return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
    }

    function applyFocusStyles() {
        if (!nodeSel) return;
        if (!state.focusNodeId) {
            nodeSel.classed("dim", false).classed("selected", false);
            if (linkSel) linkSel.classed("dim", false);
            return;
        }
        const connected = new Set([state.focusNodeId]);
        (linkSel ? linkSel.data() : []).forEach((l) => {
            const s = typeof l.source === "object" ? l.source.id : l.source;
            const t = typeof l.target === "object" ? l.target.id : l.target;
            if (s === state.focusNodeId) connected.add(t);
            if (t === state.focusNodeId) connected.add(s);
        });
        nodeSel.classed("selected", (d) => d.id === state.focusNodeId);
        nodeSel.classed("dim", (d) => !connected.has(d.id));
        if (linkSel) {
            linkSel.classed("dim", (d) => {
                const s = typeof d.source === "object" ? d.source.id : d.source;
                const t = typeof d.target === "object" ? d.target.id : d.target;
                return s !== state.focusNodeId && t !== state.focusNodeId;
            });
        }
    }

    function updateFocusChip() {
        const chip = document.getElementById("graphFocus");
        const clear = document.getElementById("clearFocus");
        if (state.focusNodeId && nodesById.has(state.focusNodeId)) {
            chip.textContent = "\u25C9 " + nodesById.get(state.focusNodeId).label;
            chip.classList.remove("hidden");
            clear.classList.remove("hidden");
        } else {
            chip.classList.add("hidden");
            clear.classList.add("hidden");
        }
    }

    // ---- Attack path table -------------------------------------------------
    function buildPathRows(base) {
        let edges = attackPathEdges(base);
        if (state.tier0RolesOnly) {
            const tier0Roles = new Set(edges.filter((e) => e.properties && e.properties.tier0breach).map((e) => e.target));
            edges = edges.filter((e) => tier0Roles.has(e.target));
        }
        return edges.map((e) => {
            const sN = nodesById.get(e.source);
            const tN = nodesById.get(e.target);
            const p = e.properties || {};
            return {
                sourceId: e.source,
                targetId: e.target,
                kind: e.kind,
                pathKey: edgeKey(e),
                kindLabel: edgeLabel(e.kind),
                principalName: sN ? sN.label : e.source,
                principalType: sN ? BUCKETS[sN.bucket].label.replace(/s$/, "") : "\u2014",
                principalTier: p.principaltier,
                targetName: tN ? tN.label : e.target,
                serviceTier: p.servicetier,
                service: p.service || "\u2014",
                scope: p.roleassignmentscopename || "\u2014",
                system: p.rbacsystem || "\u2014",
                pim: p.pimassignmenttype || "\u2014",
                tierbreach: !!p.tierbreach,
                tier0breach: !!p.tier0breach,
            };
        });
    }

    function renderPathTable(base) {
        const allRows = buildPathRows(base);
        currentPaths = allRows;
        // In the Full graph view this table lists every tier-flagged edge (not just
        // breaches), so the section label reflects that instead of overpromising.
        document.getElementById("pathTableTitle").textContent =
            state.view === "all" ? "Tier-crossing edges" : "Attack path edges";
        document.getElementById("pathCount").textContent = allRows.length.toLocaleString() + " edge(s)";
        const rows = allRows.slice(0, pathLimit);

        const tbody = document.querySelector("#pathTable tbody");
        const reviewIds = window.EOReview ? EOReview.idsSet() : new Set();
        tbody.innerHTML = rows
            .map((r, i) => {
                const starId = window.EOReview
                    ? EOReview.makeId("role", r.system, r.targetName, r.scope)
                    : "";
                const star = window.EOReview
                    ? EOReview.starHtml(starId, undefined, reviewIds.has(starId)).replace("<button ", `<button data-eo-id="${esc(starId)}" data-star="${i}" `)
                    : "";
                return (
                    `<tr class="path-row${r.pathKey === state.selectedPathKey ? " selected" : ""}" data-i="${i}">` +
                    `<td class="cell-strong">${esc(r.principalName)}</td>` +
                    `<td>${esc(r.principalType)}</td>` +
                    `<td>${tierBadge(r.principalTier)}</td>` +
                    `<td><span class="edge-chip${r.tierbreach ? " breach" : ""}">${esc(r.kindLabel)}</span></td>` +
                    `<td>${esc(r.targetName)}</td>` +
                    `<td>${tierBadge(r.serviceTier)}</td>` +
                    `<td>${esc(r.service)}</td>` +
                    `<td>${esc(r.scope)}</td>` +
                    `<td>${esc(r.system)}</td>` +
                    `<td>${esc(r.pim)}</td>` +
                    `<td>${star}</td>` +
                    `</tr>`
                );
            })
            .join("");

        renderPager(allRows.length);
    }

    // Delegated click handling for the attack path table: one listener on the tbody
    // instead of per-row/per-star listeners re-attached on every render (with "Show
    // all" this can be thousands of rows in large environments).
    document.querySelector("#pathTable tbody").addEventListener("click", (ev) => {
        const starBtn = ev.target.closest("[data-star]");
        if (starBtn) {
            ev.stopPropagation();
            const r = currentPaths[Number(starBtn.dataset.star)];
            if (!r || !window.EOReview) return;
            const on = EOReview.toggle({
                id: EOReview.makeId("role", r.system, r.targetName, r.scope),
                kind: "Role",
                system: r.system,
                name: r.targetName,
                scope: r.scope,
                tier: tierName(r.serviceTier),
                hash: edgeHash(r),
            });
            EOReview.updateStar(starBtn, on);
            return;
        }
        const tr = ev.target.closest("tr.path-row");
        if (!tr) return;
        const r = currentPaths[Number(tr.dataset.i)];
        if (!r) return;
        state.selectedPathKey = state.selectedPathKey === r.pathKey ? null : r.pathKey;
        state.focusNodeId = r.sourceId;
        updateFocusChip();
        render();
        setDeepLink(edgeHash(r));
        document.querySelector(".apm-canvas-wrap").scrollIntoView({ behavior: "smooth", block: "center" });
    });

    function renderPager(total) {
        const host = document.getElementById("pathPager");
        if (total <= pathLimit) {
            host.classList.add("hidden");
            host.innerHTML = "";
            return;
        }
        host.classList.remove("hidden");
        host.innerHTML =
            `<span>Showing ${Math.min(pathLimit, total).toLocaleString()} of ${total.toLocaleString()} row(s)</span>` +
            `<button class="btn small" data-more>Show ${Math.min(PATH_PAGE_STEP, total - pathLimit).toLocaleString()} more</button>` +
            `<button class="btn small" data-all>Show all</button>`;
        // Pager changes only the table page - re-render the table alone instead of
        // rebuilding the whole graph and restarting the force simulation.
        host.querySelector("[data-more]").addEventListener("click", () => {
            pathLimit += PATH_PAGE_STEP;
            if (lastRenderBase) renderPathTable(lastRenderBase); else render();
        });
        host.querySelector("[data-all]").addEventListener("click", () => {
            pathLimit = total;
            if (lastRenderBase) renderPathTable(lastRenderBase); else render();
        });
    }

    // ---- Drawers -------------------------------------------------------------
    const drawer = document.getElementById("drawer");
    const backdrop = document.getElementById("drawerBackdrop");
    let drawerReturnFocus = null; // element focused before the dialog opened
    function openDrawer(title, html) {
        document.getElementById("drawerTitle").textContent = title;
        document.getElementById("drawerBody").innerHTML = html;
        if (!drawer.classList.contains("open")) drawerReturnFocus = document.activeElement;
        drawer.classList.add("open");
        backdrop.classList.add("open");
        drawer.focus();
    }
    function closeDrawer() {
        const wasOpen = drawer.classList.contains("open");
        drawer.classList.remove("open");
        backdrop.classList.remove("open");
        if (wasOpen && drawerReturnFocus && typeof drawerReturnFocus.focus === "function") {
            drawerReturnFocus.focus();
        }
        drawerReturnFocus = null;
    }
    document.getElementById("drawerClose").addEventListener("click", closeDrawer);
    backdrop.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeDrawer();
    });

    function propsGrid(pairs) {
        return (
            '<div class="apm-props">' +
            pairs
                .filter(([, v]) => v !== undefined && v !== null && v !== "")
                .map(([k, v]) => `<span class="k">${esc(propLabel(k))}</span><span class="v">${formatVal(v)}</span>`)
                .join("") +
            "</div>"
        );
    }
    function formatVal(v) {
        if (Array.isArray(v)) return v.length ? v.map((x) => `<code>${esc(x)}</code>`).join(" ") : "\u2014";
        if (typeof v === "boolean") return v ? "Yes" : "No";
        return esc(String(v));
    }

    // Known attack path callout for the node/edge drawer, linking each documented
    // technique to its full write-up in the Classification Explorer.
    function attackPathCalloutHtml(paths) {
        if (!paths.length) return "";
        const items = paths
            .map(
                (p) =>
                    `<div><a href="${esc(attackPathLink(p.id))}" target="_blank" rel="noopener noreferrer">${esc(p.name)} &#8599;</a></div>`
            )
            .join("");
        return (
            `<div class="callout attack"><div class="callout-title">\u26A0 Known attack path${paths.length === 1 ? "" : "s"}</div>` +
            `Referenced by ${paths.length} documented privilege-escalation path${paths.length === 1 ? "" : "s"} in the Classification Explorer catalog. Treat this access as high-risk and prioritise least privilege, scoping and monitoring.` +
            `<div style="margin-top:8px;display:grid;gap:4px;">${items}</div></div>`
        );
    }

    // Edges where nodeId is the source of an EO_ClassifiedViaObject relationship - "why"
    // this principal/assignment was tagged with its classification, and by which object.
    function classifiedViaTargets(nodeId) {
        const rows = [];
        DATA.edges.forEach((e) => {
            if (e.kind === "EO_ClassifiedViaObject" && e.source === nodeId) {
                rows.push({ node: nodesById.get(e.target), props: e.properties || {} });
            }
        });
        return rows;
    }
    function classifiedViaHtml(nodeId) {
        const rows = classifiedViaTargets(nodeId);
        if (!rows.length) return "";
        const items = rows
            .map((r) => {
                const label = r.node ? r.node.label : "(unresolved object)";
                const p = r.props;
                return (
                    `<div class="apm-related-row"${r.node ? ` data-node="${esc(r.node.id)}"` : ' style="cursor:default;"'}>` +
                    `<span class="cell-strong">${esc(label)}</span>` +
                    (p.admintierlevelname ? tierBadge(p.admintierlevelname) : "") +
                    ` <span class="muted" style="font-size:12px;">via ${esc(p.taggedby || "TaggedBy")}${p.taggedbyrolesystem ? " (" + esc(p.taggedbyrolesystem) + ")" : ""
                    }</span></div>`
                );
            })
            .join("");
        return `<div class="section-title">Classified via (${rows.length})</div><div class="apm-related-list">${items}</div>`;
    }

    // Edges where nodeId is the source of an EO_ScopedViaResource relationship - why this
    // Azure role assignment's *resource scope* (RoleAssignmentScopeId, and everything above
    // it in the ARM hierarchy) is Tier0/Tier1: a resource at/below that scope (the target
    // node here) hosts a privileged managed identity/application.
    function scopedViaResourceTargets(nodeId) {
        const rows = [];
        DATA.edges.forEach((e) => {
            if (e.kind === "EO_ScopedViaResource" && e.source === nodeId) {
                rows.push({ node: nodesById.get(e.target), props: e.properties || {} });
            }
        });
        return rows;
    }
    function scopedViaResourceHtml(nodeId) {
        const rows = scopedViaResourceTargets(nodeId);
        if (!rows.length) return "";
        const items = rows
            .map((r) => {
                const label = r.node ? r.node.label : r.props.resourcename || "(unresolved resource)";
                const p = r.props;
                return (
                    `<div class="apm-related-row"${r.node ? ` data-node="${esc(r.node.id)}"` : ' style="cursor:default;"'}>` +
                    `<span class="cell-strong">${esc(label)}</span>` +
                    (p.eamtier ? tierBadge(p.eamtier) : "") +
                    `<br/><span class="muted" style="font-size:12px;">${esc(p.reason || "")}</span></div>`
                );
            })
            .join("");
        return `<div class="section-title">Why Tier0/Tier1 resource scope (${rows.length})</div><div class="apm-related-list">${items}</div>`;
    }

    // Other privileged objects (via their own role assignment) sharing this role
    // assignment's exact RBAC scope, and principals reaching this node via EO_ScopedTo /
    // EO_ClassifiedViaObject (i.e. this node itself is a scope or classification object).
    function relatedScopeHtml(n) {
        let html = "";
        const siblings = scopedSiblings(n);
        if (siblings.length) {
            const rows = siblings
                .map((s) => {
                    const principalId = assignmentPrincipal.get(s.id);
                    const pN = principalId ? nodesById.get(principalId) : null;
                    return (
                        `<div class="apm-related-row" data-node="${esc(s.id)}">` +
                        `<span class="cell-strong">${esc(pN ? pN.label : s.label)}</span>` +
                        (pN && pN.tierName ? tierBadge(pN.tierName) : "") +
                        ` <span class="edge-chip">${esc(s.props.roledefinitionname || s.label)}</span></div>`
                    );
                })
                .join("");
            html +=
                `<div class="callout scope"><div class="callout-title">Scope: ${esc(n.props.roleassignmentscopename || n.props.roleassignmentscopeid || "")}</div>` +
                `<div class="section-title">Other privileged objects sharing this scope (${siblings.length})</div>` +
                `<div class="apm-related-list">${rows}</div></div>`;
        }
        const related = scopeRelatedPrincipals(n.id);
        if (related.length) {
            const rows = related
                .map(
                    (p) =>
                        `<div class="apm-related-row" data-node="${esc(p.id)}">` +
                        `<span class="cell-strong">${esc(p.label)}</span>` +
                        (p.tierName ? tierBadge(p.tierName) : "") +
                        ` <span class="edge-chip">${esc(BUCKETS[p.bucket].label.replace(/s$/, ""))}</span></div>`
                )
                .join("");
            html +=
                `<div class="section-title">Objects scoped/classified via this node (${related.length})</div>` +
                `<div class="apm-related-list">${rows}</div>`;
        }
        return html;
    }

    function openNodeDrawer(n) {
        const bucket = BUCKETS[n.bucket];
        const paths = nodeAttackPaths(n);
        const chips =
            `<span class="chip brand">${esc(bucket.label.replace(/s$/, ""))}</span>` +
            (n.tierName ? tierBadge(n.tierName) : "") +
            (paths.length
                ? `<span class="chip attack" title="Referenced by a known documented attack path">\u26A0 ${paths.length === 1 ? "attack path" : paths.length + " attack paths"
                }</span>`
                : "") +
            (window.EOReview && n.bucket === "role" ? '<button type="button" id="apmRoleStar" class="eo-star" title="Add to review list">&#9734;</button>' : "");
        const propPairs = Object.keys(n.props)
            .sort()
            .map((k) => [k, n.props[k]]);
        const body =
            `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">${chips}</div>` +
            attackPathCalloutHtml(paths) +
            classifiedViaHtml(n.id) +
            scopedViaResourceHtml(n.id) +
            relatedScopeHtml(n) +
            `<div class="section-title">Node id</div><p class="cell-mono" style="word-break:break-all;">${esc(n.id)}</p>` +
            `<div class="section-title">Kinds</div><p>${n.kinds.map((k) => `<span class="edge-chip">${esc(stripKindPrefix(k))}</span>`).join(" ")}</p>` +
            `<button type="button" id="apmExpandContext" class="btn small" style="margin:10px 0;">Show full context in graph</button>` +
            `<div class="section-title">Properties (incl. classification &amp; enrichment)</div>${propsGrid(propPairs)}`;
        openDrawer(n.label, body);

        document.querySelectorAll("#drawerBody [data-node]").forEach((row) => {
            row.addEventListener("click", () => {
                const target = nodesById.get(row.getAttribute("data-node"));
                if (target) openNodeDrawer(target);
            });
        });
        const expandBtn = document.getElementById("apmExpandContext");
        if (expandBtn) {
            expandBtn.addEventListener("click", () => {
                expandFocusNodeId = n.id;
                state.focusNodeId = n.id;
                updateFocusChip();
                render();
            });
        }

        if (window.EOReview && n.bucket === "role") {
            const btn = document.getElementById("apmRoleStar");
            const reviewId = EOReview.makeId("role", n.props.rbacsystem || "", n.props.roledefinitionname || n.label, "graph-node");
            EOReview.updateStar(btn, EOReview.has(reviewId));
            btn.addEventListener("click", () => {
                const on = EOReview.toggle({
                    id: reviewId,
                    kind: "Role",
                    system: n.props.rbacsystem || "",
                    name: n.props.roledefinitionname || n.label,
                    scope: "Access Path Map graph node",
                    tier: n.tierName || "",
                    hash: nodeHash(n),
                });
                EOReview.updateStar(btn, on);
            });
        }
    }

    function openEdgeDrawer(l) {
        const sN = nodesById.get(typeof l.source === "object" ? l.source.id : l.source);
        const tN = nodesById.get(typeof l.target === "object" ? l.target.id : l.target);
        const breach = l.properties && l.properties.tierbreach;
        const paths = edgeAttackPaths(l);
        const chips =
            `<span class="edge-chip${breach ? " breach" : ""}">${esc(edgeLabel(l.kind))}</span>` +
            (l.properties && l.properties.rbacsystem ? `<span class="chip brand">${esc(l.properties.rbacsystem)}</span>` : "") +
            (breach ? '<span class="chip priv">Tier breach</span>' : "") +
            (l.properties && l.properties.tier0breach ? '<span class="chip priv">Tier 0</span>' : "") +
            (paths.length
                ? `<span class="chip attack" title="Referenced by a known documented attack path">\u26A0 ${paths.length === 1 ? "attack path" : paths.length + " attack paths"
                }</span>`
                : "");
        const propPairs = Object.keys(l.properties || {})
            .sort()
            .map((k) => [k, l.properties[k]]);
        const taggedByHtml =
            l.properties && l.properties.taggedby
                ? `<div class="callout scope"><div class="callout-title">Classification provenance</div>` +
                `Tagged by <strong>${esc(l.properties.taggedby)}</strong>${l.properties.taggedbyrolesystem ? " (" + esc(l.properties.taggedbyrolesystem) + ")" : ""
                }.</div>`
                : "";
        const body =
            `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">${chips}</div>` +
            attackPathCalloutHtml(paths) +
            `<div class="callout"><div class="callout-title">Relationship</div>` +
            `<strong>${esc(sN ? sN.label : "")}</strong> &#8594; <strong>${esc(tN ? tN.label : "")}</strong> ` +
            `via <span class="edge-chip">${esc(edgeLabel(l.kind))}</span></div>` +
            taggedByHtml +
            `<div class="section-title">Properties</div>${propsGrid(propPairs)}`;
        openDrawer(edgeLabel(l.kind), body);
    }

    function tierName(n) {
        return { 0: "ControlPlane", 1: "ManagementPlane", 2: "UserAccess" }[n] || "";
    }
    function tierBadge(t) {
        const name = typeof t === "number" ? tierName(t) : t;
        if (!name) return "";
        const cls = TIER_BADGE_CLASS[name] || "tier-unclassified";
        return `<span class="tier-badge ${cls}"><span class="tier-dot"></span>${esc(name)}</span>`;
    }

    // ---- Tooltips ------------------------------------------------------------
    function nodeTooltip(n) {
        return `<b>${esc(n.label)}</b><br>${esc(BUCKETS[n.bucket].label.replace(/s$/, ""))}${n.tierName ? " &middot; " + esc(n.tierName) : ""
            }`;
    }
    function edgeTooltip(l) {
        const sN = nodesById.get(typeof l.source === "object" ? l.source.id : l.source);
        const tN = nodesById.get(typeof l.target === "object" ? l.target.id : l.target);
        return `${esc(sN ? sN.label : "")} &#8594; ${esc(tN ? tN.label : "")}<br><b>${esc(edgeLabel(l.kind))}</b>`;
    }
    function showTip(ev, html) {
        tooltip.classed("hidden", false).html(html).style("left", ev.clientX + 14 + "px").style("top", ev.clientY + 14 + "px");
    }
    function hideTip() {
        tooltip.classed("hidden", true);
    }

    // ---- Node context menu (right-click) --------------------------------------
    // Right-clicking a graph node offers the same "Show full context in graph"
    // expansion the node drawer exposes, without having to open the drawer first.
    const ctxMenu = document.createElement("div");
    ctxMenu.className = "apm-context-menu hidden";
    document.body.appendChild(ctxMenu);
    function hideNodeContextMenu() {
        ctxMenu.classList.add("hidden");
    }
    document.addEventListener("click", hideNodeContextMenu);
    document.addEventListener("contextmenu", (ev) => {
        // Right-click anywhere that is not a graph node closes an open menu.
        if (!ev.target.closest || !ev.target.closest(".apm-node")) hideNodeContextMenu();
    });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") hideNodeContextMenu();
    });

    function showNodeContextMenu(ev, d) {
        ev.preventDefault();
        ev.stopPropagation();
        hideTip();
        ctxMenu.innerHTML =
            `<div class="ctx-title">${esc(truncate(d.label, 34))}</div>` +
            `<button type="button" data-act="context">Show full context in graph</button>` +
            `<button type="button" data-act="details">Open details</button>` +
            `<button type="button" data-act="focus">Focus connections</button>`;
        ctxMenu.classList.remove("hidden");
        const mw = ctxMenu.offsetWidth || 220;
        const mh = ctxMenu.offsetHeight || 130;
        ctxMenu.style.left = Math.min(ev.clientX, window.innerWidth - mw - 8) + "px";
        ctxMenu.style.top = Math.min(ev.clientY, window.innerHeight - mh - 8) + "px";
        ctxMenu.querySelectorAll("button").forEach((btn) =>
            btn.addEventListener("click", (clickEv) => {
                clickEv.stopPropagation();
                const act = btn.dataset.act;
                hideNodeContextMenu();
                state.focusNodeId = d.id;
                updateFocusChip();
                if (act === "context") {
                    expandFocusNodeId = d.id;
                    render();
                    setDeepLink(nodeHash(d));
                } else if (act === "details") {
                    applyFocusStyles();
                    openNodeDrawer(d);
                    setDeepLink(nodeHash(d));
                } else {
                    applyFocusStyles();
                    setDeepLink(nodeHash(d));
                }
            })
        );
    }

    // ---- Deep links (bookmark a node or edge selection) -----------------------
    function nodeHash(n) {
        return "#node=" + encodeURIComponent(n.id);
    }
    function edgeHash(l) {
        const s = typeof l.sourceId !== "undefined" ? l.sourceId : typeof l.source === "object" ? l.source.id : l.source;
        const t = typeof l.targetId !== "undefined" ? l.targetId : typeof l.target === "object" ? l.target.id : l.target;
        return "#edge=" + encodeURIComponent([s, l.kind, t].join("||"));
    }
    function edgeKey(l) {
        const s = typeof l.sourceId !== "undefined" ? l.sourceId : typeof l.source === "object" ? l.source.id : l.source;
        const t = typeof l.targetId !== "undefined" ? l.targetId : typeof l.target === "object" ? l.target.id : l.target;
        return [s, l.kind, t].join("||");
    }
    function setDeepLink(hash) {
        history.replaceState(null, "", hash);
    }

    function applyDeepLink() {
        const h = location.hash || "";
        let m = h.match(/^#node=(.+)$/);
        if (m) {
            const id = decodeURIComponent(m[1]);
            if (nodesById.has(id)) {
                state.focusNodeId = id;
                updateFocusChip();
                applyFocusStyles();
                openNodeDrawer(nodesById.get(id));
                document.querySelector(".apm-canvas-wrap").scrollIntoView({ behavior: "smooth", block: "center" });
            }
            return;
        }
        m = h.match(/^#edge=(.+)$/);
        if (m) {
            const [s, kind, t] = decodeURIComponent(m[1]).split("||");
            const findLink = () =>
                (linkSel ? linkSel.data() : []).find((l) => {
                    const ls = typeof l.source === "object" ? l.source.id : l.source;
                    const lt = typeof l.target === "object" ? l.target.id : l.target;
                    return ls === s && lt === t && l.kind === kind;
                });
            let link = findLink();
            if (!link && state.view !== "all" && DATA.edges.some((e) => e.source === s && e.target === t && e.kind === kind)) {
                // The bookmarked edge exists in the dataset but not in the current
                // (breach-only) view — switch to the full graph so it resolves.
                state.view = "all";
                document.querySelectorAll(".nav-item.view-item").forEach((n) => n.classList.toggle("active", n.dataset.view === "all"));
                render();
                link = findLink();
            }
            if (link) {
                openEdgeDrawer(link);
                state.focusNodeId = s;
                updateFocusChip();
                applyFocusStyles();
            } else if (nodesById.has(s)) {
                state.focusNodeId = s;
                updateFocusChip();
                applyFocusStyles();
            }
            document.querySelector(".apm-canvas-wrap").scrollIntoView({ behavior: "smooth", block: "center" });
        }
    }
    window.addEventListener("hashchange", applyDeepLink);

    // ---- CSV export --------------------------------------------------------
    function exportCsv() {
        const cols = [
            ["principalName", "Principal"],
            ["principalType", "Type"],
            ["principalTier", "PrincipalTier"],
            ["kindLabel", "Relationship"],
            ["targetName", "Target"],
            ["serviceTier", "ServiceTier"],
            ["service", "Service"],
            ["scope", "Scope"],
            ["system", "System"],
            ["pim", "PIMAssignmentType"],
            ["tierbreach", "TierBreach"],
            ["tier0breach", "Tier0Breach"],
        ];
        const csvCell = (v) => {
            const s = v === null || v === undefined ? "" : String(v);
            // Neutralise spreadsheet formula injection before RFC-4180 quoting. Excel and Sheets execute a
            // cell whose text begins with = + - @ (or a leading tab/CR), and these exports carry tenant
            // display names, which are attacker-influenceable (a guest can set their own). A leading
            // apostrophe forces the cell to be treated as literal text.
            var csvSafe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
            return /[",\n\r]/.test(csvSafe) ? '"' + csvSafe.replace(/"/g, '""') + '"' : csvSafe;
        };
        const lines = [cols.map((c) => c[1]).join(",")];
        currentPaths.forEach((r) => lines.push(cols.map((c) => csvCell(r[c[0]])).join(",")));
        const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "entraops-attack-paths.csv";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ---- Helpers -----------------------------------------------------------
    function truncate(s, n) {
        s = String(s);
        return s.length > n ? s.slice(0, n - 1) + "\u2026" : s;
    }
    function esc(s) {
        return String(s).replace(/[&<>"']/g, (c) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
        }[c]));
    }

    // ---- Main render -----------------------------------------------------------
    // Last computed edge base, so table-only interactions (pager) can re-render the
    // table without rebuilding the graph and restarting the force simulation.
    let lastRenderBase = null;
    function render() {
        // The "Only documented attack paths" filter is applied once here so the
        // graph, the stats tiles and the attack path table all agree on the same
        // edge set (it used to be graph-only).
        let base = baseFilteredEdges();
        if (state.knownAttackPathsOnly) {
            base = base.filter((e) => attackPathNodeIds.has(e.source) || attackPathNodeIds.has(e.target));
        }
        lastRenderBase = base;
        updateViewCounts(base);
        renderStats(base);
        renderPathTable(base);
        const graph = buildGraph(base);
        drawGraph(graph);
    }

    // Debounced: a window drag fires dozens of resize events per second, and each restart
    // re-heats the (up to 700-link) simulation. Same 180ms pattern as TierBreachAnalyzer.
    let resizeTimer = null;
    window.addEventListener("resize", () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if (simulation) {
                const wrap = document.querySelector(".apm-canvas-wrap");
                simulation.force("center", d3.forceCenter(wrap.clientWidth / 2, 320)).alpha(0.3).restart();
            }
        }, 180);
    });

    render();
    applyDeepLink();
})();
