/*
 * EntraOps Dashboard (Enterprise Access Model Dashboard)
 *
 * Static-web counterpart of the "EntraOps Privileged EAM - Overview" Azure
 * workbook, rendered from the EntraOps Privileged EAM export.
 *
 * Data contract: window.ENTRAOPS_EAM_DATA = { generatedFrom: [..], objects: [..] }
 * written by New-EntraOpsPrivilegedEamDashboardData.
 *
 * The filter model mirrors the workbook parameters:
 *   RoleSystem, AdminTierLevelName (RBAC Tier Level), Service, ObjectType
 *   (Principal Type), LinkedIdentity, PrivilegedType (Tenant Governance /
 *   Multi-Tenant Apps / B2B Collaboration / Local Identities) and a free-text
 *   search across principal display name, role name, scope name and role actions.
 * plus the click-to-filter exports of the workbook visualizations:
 *   SyncSource, RestrictedManagement, AssignmentType, ObjectAdminTierLevelName,
 *   RoleClassificationAdminTierLevelName, ObjectId, SelectedRoleAssignmentIds.
 */
(function () {
    "use strict";

    const DATA = window.ENTRAOPS_EAM_DATA;
    if (DATA && typeof DATA.tenantName === "string" && DATA.tenantName.trim()) {
        document.getElementById("tenantName").textContent = DATA.tenantName.trim();
    }
    if (window.EOReview) {
        EOReview.init({ app: "EamDashboard", appLabel: "EAM Dashboard" });
    }
    if (!DATA || !Array.isArray(DATA.objects)) {
        document.addEventListener("DOMContentLoaded", function () {
            // EONotifications never initializes on this path, so the bell would sit
            // in the app bar without a handler - hide it.
            const bell = document.getElementById("notificationButton");
            if (bell) bell.classList.add("hidden");
            const app = document.getElementById("app");
            const box = document.createElement("div");
            box.className = "error-box";
            box.innerHTML =
                "<strong>No dataset found.</strong><br>" +
                "Generate <code>data/eam-dashboard-data.js</code> from your EntraOps Privileged EAM export first:" +
                "<br><br><code>Import-Module ./EntraOps; New-EntraOpsPrivilegedEamDashboardData</code>" +
                "<br><br>then reload this page.";
            const head = app.querySelector(".page-head");
            if (head) head.after(box);
            else app.appendChild(box);
        });
        return;
    }
    if (window.EONotifications) {
        EONotifications.init({
            appId: "EamDashboard",
            changeSetId: DATA.changeSetId || DATA.generatedAt || "none",
            items: DATA.notifications || [],
        });
    }

    // ---- Constants (workbook icons + Enterprise Access Model palette) -------
    const TIER_ORDER = ["ControlPlane", "ManagementPlane", "WorkloadPlane", "UserAccess", "Unclassified"];

    function assignmentKey(assignment) {
        return assignment.roleAssignmentInstanceId || assignment.roleAssignmentId || "";
    }

    const TIER_COLOR = {
        ControlPlane: "#a4262c",
        ManagementPlane: "#c07807",
        WorkloadPlane: "#0078d4",
        UserAccess: "#0e700e",
        Unclassified: "#8a8886",
    };
    const TIER_BADGE_CLASS = {
        ControlPlane: "tier-controlplane",
        ManagementPlane: "tier-managementplane",
        WorkloadPlane: "tier-workloadplane",
        UserAccess: "tier-useraccess",
        Unclassified: "tier-unclassified",
    };
    const TIER_TEXT = {
        ControlPlane: "Control Plane",
        ManagementPlane: "Management Plane",
        WorkloadPlane: "Workload Plane",
        UserAccess: "User Access",
        Unclassified: "Unclassified",
    };
    // Workbook: Person / PersonWithFriend / Capture / Question threshold icons.
    const TYPE_ICON = {
        user: ["&#128100;", "User"],
        group: ["&#128101;", "Group"],
        serviceprincipal: ["&#9881;&#65039;", "Service Principal"],
        unknown: ["&#10067;", "Unknown"],
    };
    // Workbook: Key / AzurePortal / Share / Connect / Tools threshold icons.
    const SYSTEM_ICON = {
        EntraID: ["&#128273;", "Entra ID"],
        Azure: ["&#9729;&#65039;", "Azure"],
        IdentityGovernance: ["&#128257;", "Identity Governance"],
        ResourceApps: ["&#128268;", "Resource Apps"],
        DeviceManagement: ["&#128736;&#65039;", "Device Management"],
        Defender: ["&#128737;&#65039;", "Defender"],
    };
    // Workbook: success / warning / error / cancelled threshold icons.
    const RM_ICON = {
        Applied: ['<span class="ico-glyph rm-applied">&#10004;</span>', "Applied"],
        Conflict: ['<span class="ico-glyph rm-conflict">&#9888;</span>', "Conflict"],
        "Not applied": ['<span class="ico-glyph rm-notapplied">&#10006;</span>', "Not applied"],
        "Not available": ['<span class="ico-glyph rm-notavailable">&#8856;</span>', "Not available"],
    };
    const PIE_PALETTE = ["#0078d4", "#c07807", "#a4262c", "#0e700e", "#5c2d91", "#038387", "#8a8886", "#986f0b"];

    // ---- State (workbook parameters + exports) ------------------------------
    const state = {
        roleSystems: null,       // null = all, else Set
        tierLevels: null,        // RBAC Tier Level (classification AdminTierLevelName)
        services: null,
        objectTypes: null,       // Principal Type
        linkedIdentity: "",      // AssociatedWorkAccount object id (or ObjectId)
        privilegedTypes: null,   // Privileged Type (Tenant Governance / Multi-Tenant Apps / ...)
        displayName: "",         // Search: display name, role name, scope name, role actions
        // Click-to-filter exports:
        syncSource: "*",
        restrictedManagement: "*",
        assignmentType: "*",
        objectTier: "*",         // ObjectAdminTierLevelName
        accessTier: "*",         // RoleClassificationAdminTierLevelName
        selectedObjectId: "*",
        selectedAssignmentIds: new Set(),
        // Principals (object ids) checked for side-by-side comparison.
        compareIds: new Set(),
        // Rows displayed per grid (paged; headers stay pinned to the viewport).
        limits: { asset: 50, assignment: 50, classification: 50 },
        // Column sort per grid: null = default order, else { column, dir } with
        // dir 1 = ascending, -1 = descending (column = thead cell index).
        sortOrders: { asset: null, assignment: null },
    };

    const PAGE_STEP = 250;

    // ---- Resizable grid columns -----------------------------------------------
    // Headers are static while table bodies are re-rendered, so initialize this
    // once and retain each operator's widths in browser storage.
    const GRID_RESIZE_STORAGE_KEY = "entraops.eamDashboard.columnWidths";
    const GRID_MIN_COLUMN_WIDTH = 72;

    function loadGridColumnWidths() {
        try {
            return JSON.parse(localStorage.getItem(GRID_RESIZE_STORAGE_KEY)) || {};
        } catch (_) {
            return {};
        }
    }

    function initializeGridColumnResizing() {
        const widths = loadGridColumnWidths();
        const narrowViewport = window.matchMedia("(max-width: 860px)");
        document.querySelectorAll("table.grid-table[id]").forEach((table) => {
            const headers = Array.from(table.querySelectorAll("thead th"));
            const applySavedWidths = () => {
                headers.forEach((header, index) => {
                    if (narrowViewport.matches) {
                        clearColumnWidth(table, index);
                        return;
                    }
                    const savedWidth = Number(widths[table.id + ":" + index]);
                    if (savedWidth >= GRID_MIN_COLUMN_WIDTH) setColumnWidth(table, index, savedWidth);
                });
            };
            applySavedWidths();
            narrowViewport.addEventListener("change", applySavedWidths);
            headers.forEach((header, index) => {
                const widthKey = table.id + ":" + index;

                const handle = document.createElement("span");
                handle.className = "column-resize-handle";
                handle.tabIndex = 0;
                handle.setAttribute("role", "separator");
                handle.setAttribute("aria-orientation", "vertical");
                handle.setAttribute("aria-label", "Resize " + header.textContent.trim() + " column");
                header.title = header.textContent.trim();
                header.classList.add("resizable-column");
                header.appendChild(handle);

                const resizeBy = (delta) => {
                    const currentWidth = header.getBoundingClientRect().width;
                    const nextWidth = Math.max(GRID_MIN_COLUMN_WIDTH, Math.round(currentWidth + delta));
                    setColumnWidth(table, index, nextWidth);
                    widths[widthKey] = nextWidth;
                    try { localStorage.setItem(GRID_RESIZE_STORAGE_KEY, JSON.stringify(widths)); } catch (_) { }
                };

                handle.addEventListener("pointerdown", (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const startX = event.clientX;
                    const startWidth = header.getBoundingClientRect().width;
                    table.classList.add("is-resizing");
                    document.body.classList.add("column-resizing");
                    handle.setPointerCapture(event.pointerId);

                    const onPointerMove = (moveEvent) => {
                        const nextWidth = Math.max(GRID_MIN_COLUMN_WIDTH, Math.round(startWidth + moveEvent.clientX - startX));
                        setColumnWidth(table, index, nextWidth);
                        widths[widthKey] = nextWidth;
                    };
                    const finish = () => {
                        table.classList.remove("is-resizing");
                        document.body.classList.remove("column-resizing");
                        try { localStorage.setItem(GRID_RESIZE_STORAGE_KEY, JSON.stringify(widths)); } catch (_) { }
                        handle.removeEventListener("pointermove", onPointerMove);
                        handle.removeEventListener("pointerup", finish);
                        handle.removeEventListener("pointercancel", finish);
                    };
                    handle.addEventListener("pointermove", onPointerMove);
                    handle.addEventListener("pointerup", finish);
                    handle.addEventListener("pointercancel", finish);
                });
                handle.addEventListener("keydown", (event) => {
                    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
                    event.preventDefault();
                    resizeBy((event.key === "ArrowRight" ? 1 : -1) * (event.shiftKey ? 40 : 10));
                });
            });
        });
    }

    function setColumnWidth(table, index, width) {
        const cells = table.querySelectorAll("tr > :nth-child(" + (index + 1) + ")");
        cells.forEach((cell) => {
            cell.style.setProperty("width", width + "px", "important");
            cell.style.minWidth = "";
        });
    }

    function clearColumnWidth(table, index) {
        const cells = table.querySelectorAll("tr > :nth-child(" + (index + 1) + ")");
        cells.forEach((cell) => {
            cell.style.removeProperty("width");
            cell.style.minWidth = "";
        });
    }

    // ---- Sortable grid columns -----------------------------------------------
    // Click-to-sort on the asset and assignment grid headers (the .no-sort icon
    // columns keep their default cursor via CSS). Clicking a sortable header
    // cycles ascending -> descending -> default order. The sort is applied to
    // the full filtered row set BEFORE pagination slicing (see applySort call
    // sites), so it always covers every row and not just the visible page.
    function tierRank(tierName) {
        const i = TIER_ORDER.indexOf(tierName);
        return i === -1 ? TIER_ORDER.length : i;
    }

    // Per-table sort-key accessors, aligned with the thead cell indexes
    // (null = not sortable; mirrors the .no-sort headers in index.html).
    const SORT_COLUMNS = {
        asset: [
            null,                                                    // compare checkbox
            (r) => r.objectType || "",                               // Type
            (r) => (r.objectSubType || "").toLowerCase(),            // Sub type
            (r) => r._sortName,                                      // Display name
            (r) => tierRank(r.objectAdminTierLevelName),             // Object tier
            (r) => r.restrictedManagement || "",                     // Restricted management
            (r) => r.syncSource || "",                               // Sync source
            (r) => r.adminUnits.length,                              // Administrative units
            (r) => r.linkedIdentity.map((id) => String(displayNameForId(id)).toLowerCase()).sort().join(", "), // Linked identity
            (r) => Array.from(r.roleSystems).sort().join(", "),      // RBAC systems
            (r) => (r.objectId || "").toLowerCase(),                 // Object Id
            (r) => (r.objectTenantId || "").toLowerCase(),           // Object tenant Id
            null, null, null,                                        // star / info / details
        ],
        assignment: [
            null,                                                    // select checkbox
            (r) => r.roleSystem || "",                               // System
            (r) => tierRank(r.adminTierLevel),                       // Tier level
            (r) => r._sortRole,                                      // Role
            (r) => (r.roleType || "").toLowerCase(),                 // Role type
            (r) => String(r.roleAssignmentScopeName || "").toLowerCase(), // Scope
            (r) => (r.pimAssignmentType || "").toLowerCase(),        // PIM assignment
            (r) => (r.roleAssignmentType || "").toLowerCase(),       // Assignment type
            (r) => (r.eligibilityBy || "").toLowerCase(),            // Eligibility by
            (r) => (r.transitiveBy || "").toLowerCase(),             // Transitive by
            (r) => (r.transitiveByAssignment || "").toLowerCase(),   // Assignment subtype
            (r) => r.transitiveByNesting.length,                     // Nested via
            (r) => Array.from(r.services).sort().join(", ").toLowerCase(), // Service
            null, null, null,                                        // star / info / details
        ],
    };

    function applySort(rows, sortKey) {
        const sort = state.sortOrders[sortKey];
        const accessor = sort && SORT_COLUMNS[sortKey][sort.column];
        if (!accessor) return rows;
        // Decorate-sort-undecorate: compute each row's key only once (accessors
        // may join sets or resolve display names) and never mutate the cached
        // default-order array, so the third click can fall back to it cheaply.
        const dir = sort.dir;
        return rows
            .map((row) => [accessor(row), row])
            .sort((a, b) => dir * (typeof a[0] === "number" ? a[0] - b[0] : cmpStr(a[0], b[0])))
            .map((pair) => pair[1]);
    }

    function initializeGridSorting() {
        [["assetTable", "asset"], ["assignmentTable", "assignment"]].forEach(([tableId, sortKey]) => {
            const thead = document.querySelector("#" + tableId + " thead");
            const headers = Array.from(thead.querySelectorAll("th"));
            const columns = SORT_COLUMNS[sortKey];
            headers.forEach((th, index) => {
                if (th.classList.contains("no-sort") || !columns[index]) return;
                // Sortable headers become interactive: expose them to keyboard users.
                th.setAttribute("role", "button");
                th.tabIndex = 0;
                th.setAttribute("aria-label", "Sort by " + th.textContent.trim());
            });
            const toggleSort = (th) => {
                const index = headers.indexOf(th);
                if (index === -1 || th.classList.contains("no-sort") || !columns[index]) return;
                const current = state.sortOrders[sortKey];
                if (!current || current.column !== index) state.sortOrders[sortKey] = { column: index, dir: 1 };
                else if (current.dir === 1) current.dir = -1;
                else state.sortOrders[sortKey] = null; // third click: back to default order
                updateSortIndicators(headers, sortKey);
                resetPagination();
                render();
            };
            thead.addEventListener("click", (ev) => {
                // A resize drag ends with a click on the handle - never sort on it.
                if (ev.target.closest(".column-resize-handle")) return;
                const th = ev.target.closest("th");
                if (th) toggleSort(th);
            });
            thead.addEventListener("keydown", (ev) => {
                if (ev.key !== "Enter" && ev.key !== " ") return;
                // The resize handle has its own ArrowLeft/ArrowRight keyboard handler.
                if (ev.target.closest(".column-resize-handle")) return;
                const th = ev.target.closest("th");
                if (!th) return;
                ev.preventDefault();
                toggleSort(th);
            });
        });
    }

    function updateSortIndicators(headers, sortKey) {
        const sort = state.sortOrders[sortKey];
        headers.forEach((th, index) => {
            const arrow = th.querySelector(".arrow");
            if (arrow) arrow.remove();
            if (sort && sort.column === index) {
                th.setAttribute("aria-sort", sort.dir === 1 ? "ascending" : "descending");
                const indicator = document.createElement("span");
                indicator.className = "arrow";
                indicator.textContent = sort.dir === 1 ? "▲" : "▼";
                // Keep the resize handle the last child of the header cell
                // (insertBefore with a null reference appends).
                th.insertBefore(indicator, th.querySelector(".column-resize-handle"));
            } else {
                th.removeAttribute("aria-sort");
            }
        });
    }

    // ---- Option domains ------------------------------------------------------
    const allSystems = uniqueSorted(DATA.objects.map((o) => o.roleSystem));
    const allTypes = uniqueSorted(DATA.objects.map((o) => o.objectType));
    // Privileged Type categories (fixed order; computed by the data generator).
    const PRIVILEGED_TYPES = ["Tenant Governance", "Multi-Tenant Apps", "B2B Collaboration", "Local Identities"];

    function privilegedTypeOf(o) {
        // Datasets generated before the PrivilegedType column default to local.
        return o.privilegedType || "Local Identities";
    }
    const allTiers = TIER_ORDER.filter((t) =>
        DATA.objects.some((o) => (o.classification || []).some((c) => c.adminTierLevelName === t))
    );
    // Linked identities: prefer generator-resolved names, then exported objects, then the raw ID.
    // Graph and export GUID casing can differ, so normalize every key before lookup.
    const nameById = new Map();
    function rememberDisplayName(objectId, displayName) {
        if (objectId && displayName) nameById.set(String(objectId).toLowerCase(), displayName);
    }
    Object.entries(DATA.linkedIdentityDisplayNames || {}).forEach(([objectId, displayName]) =>
        rememberDisplayName(objectId, displayName)
    );
    DATA.objects.forEach((o) => rememberDisplayName(o.objectId, o.objectDisplayName));
    function displayNameForId(objectId) {
        return nameById.get(String(objectId || "").toLowerCase()) || objectId;
    }
    const linkedIdentityOptions = uniqueSorted(
        DATA.objects.flatMap((o) => asArray(o.associatedWorkAccount))
    ).map((id) => ({ id, label: displayNameForId(id) }));

    function uniqueSorted(arr) {
        return Array.from(new Set(arr.filter((v) => v !== null && v !== undefined && v !== "")))
            .sort((a, b) => String(a).localeCompare(String(b)));
    }

    // Cheap, non-locale-aware string comparison for large-scale sorts (List of
    // Privileged Assets / Role assignments / Role classification can be
    // thousands of rows in large tenants). `localeCompare` is correct but goes
    // through ICU collation on every single comparison, which dominates sort
    // time at that scale - a plain `<`/`>` comparison over a precomputed
    // lowercase key is dramatically cheaper and good enough for table sorting.
    function cmpStr(a, b) {
        return a < b ? -1 : a > b ? 1 : 0;
    }

    // ---- Filter predicates (mirroring the workbook KQL) ----------------------
    function inSel(set, value) {
        return set === null || set.has(value);
    }

    function classificationEntryMatch(o) {
        // mv-expand Classification | where AdminTierLevelName in (..) | where Service in (..)
        // -> object passes when any object-level classification entry matches both.
        if (state.tierLevels === null && state.services === null) return true;
        const entries = o.classification || [];
        if (entries.length === 0) return false;
        return entries.some(
            (c) =>
                inSel(state.tierLevels, c.adminTierLevelName) &&
                inSel(state.services, c.service)
        );
    }

    function linkedIdentityMatch(o) {
        if (!state.linkedIdentity) return true;
        const awa = asArray(o.associatedWorkAccount);
        return awa.includes(state.linkedIdentity) || o.objectId === state.linkedIdentity;
    }

    function displayNameMatch(o) {
        // Free-text search across principal display name, role name, scope name
        // and classified role actions. The searchable text per object is immutable, so it is
        // lowercased ONCE into a joined haystack on first use - the previous per-keystroke
        // .toLowerCase() of every role/scope/action string allocated hundreds of thousands of
        // strings per keypress on large tenants. A \u0001 separator between fields ensures a query can never
        // match across two adjacent values.
        if (!state.displayName) return true;
        if (o.__searchHay === undefined) {
            const parts = [o.objectDisplayName || ""];
            (o.roleAssignments || []).forEach((ra) => {
                parts.push(ra.roleDefinitionName || "", ra.roleAssignmentScopeName || "", ra.roleAssignmentScopeId || "");
                (ra.classification || []).forEach((c) => {
                    asArray(c.matchedActions).forEach((a) => parts.push(String(a)));
                });
            });
            o.__searchHay = parts.join("\u0001").toLowerCase();
        }
        return o.__searchHay.includes(state.displayName);
    }

    function baseMatch(o) {
        // Workbook parameters shared by every query.
        return (
            inSel(state.roleSystems, o.roleSystem) &&
            inSel(state.objectTypes, o.objectType) &&
            inSel(state.privilegedTypes, privilegedTypeOf(o)) &&
            classificationEntryMatch(o) &&
            linkedIdentityMatch(o) &&
            displayNameMatch(o)
        );
    }

    function syncSourceMatch(o) {
        return state.syncSource === "*" || o.syncSource === state.syncSource;
    }

    // state.objectTier is "*", one tier (a classification tile) or several tiers separated by commas (the hand-over
    // of the Privilege History tier level filter).
    function objectTierMatch(o) {
        return state.objectTier === "*" || String(state.objectTier).split(",").indexOf(o.objectAdminTierLevelName) !== -1;
    }

    function accessTierMatch(o) {
        // Workbook: parse_json(Classification) contains '{RoleClassificationAdminTierLevelName}'
        if (state.accessTier === "*") return true;
        return (o.classification || []).some((c) => c.adminTierLevelName === state.accessTier);
    }

    function restrictedManagementMatch(o) {
        return state.restrictedManagement === "*" || o.restrictedManagement === state.restrictedManagement;
    }

    function assignmentTypeMatch(o) {
        if (state.assignmentType === "*") return true;
        return (o.roleAssignments || []).some(
            (ra) => assignmentTypeOf(ra) === state.assignmentType
        );
    }

    function assignmentTypeOf(ra) {
        // Workbook: strcat(RoleAssignmentType, " ", PIMAssignmentType)
        return ((ra.roleAssignmentType || "") + " " + (ra.pimAssignmentType || "")).trim();
    }

    // ---- Filtered record sets -------------------------------------------------
    let renderCache = Object.create(null);
    const reasoningKeyCache = new WeakMap();

    function reasoningKey(reasoning) {
        if (reasoning && typeof reasoning === "object") {
            if (!reasoningKeyCache.has(reasoning)) reasoningKeyCache.set(reasoning, JSON.stringify(reasoning));
            return reasoningKeyCache.get(reasoning);
        }
        return JSON.stringify(reasoning);
    }

    function baseRecords() {
        if (!renderCache.baseRecords) renderCache.baseRecords = DATA.objects.filter(baseMatch);
        return renderCache.baseRecords;
    }

    function assetRecords() {
        // "List of Privileged Assets" query filters.
        if (!renderCache.assetRecords) {
            renderCache.assetRecords = baseRecords().filter(
                (o) =>
                    syncSourceMatch(o) &&
                    objectTierMatch(o) &&
                    accessTierMatch(o) &&
                    restrictedManagementMatch(o) &&
                    assignmentTypeMatch(o)
            );
        }
        return renderCache.assetRecords;
    }

    function drillRecords() {
        // "Related privileged role assignments" / "Related role classification" filters.
        if (!renderCache.drillRecords) {
            renderCache.drillRecords = assetRecords().filter(
                (o) => state.selectedObjectId === "*" || o.objectId === state.selectedObjectId
            );
        }
        return renderCache.drillRecords;
    }

    // ---- Filter UI -------------------------------------------------------------
    buildMultiSelect("fltRoleSystem", "RBAC System", allSystems, "roleSystems");
    buildMultiSelect("fltTierLevel", "RBAC Tier Level", allTiers, "tierLevels");
    buildMultiSelect("fltService", "Service", serviceOptions(), "services");
    buildMultiSelect("fltObjectType", "Principal Type", allTypes, "objectTypes");
    buildLinkedIdentitySelect();
    buildMultiSelect("fltPrivilegedType", "Privileged Type", PRIVILEGED_TYPES, "privilegedTypes");

    document.getElementById("fltDisplayName").addEventListener("input", debounce((e) => {
        state.displayName = e.target.value.trim().toLowerCase();
        resetSelection();
        resetPagination();
        render();
    }, 180));

    function serviceOptions() {
        // Dependent parameter: services within the currently selected systems/tiers
        // (matches the workbook's dependent Service parameter query).
        const set = new Set();
        DATA.objects.forEach((o) => {
            if (!inSel(state.roleSystems, o.roleSystem)) return;
            (o.classification || []).forEach((c) => {
                if (!inSel(state.tierLevels, c.adminTierLevelName)) return;
                if (c.service) set.add(c.service);
            });
        });
        return Array.from(set).sort((a, b) => a.localeCompare(b));
    }

    function buildMultiSelect(hostId, label, options, stateKey) {
        const host = document.getElementById(hostId);
        host.innerHTML =
            `<label>${esc(label)}</label>` +
            `<div class="dd"><button class="dd-btn" type="button">` +
            `<span class="dd-val">All</span><span class="dd-caret">&#9660;</span></button>` +
            `<div class="dd-pop hidden"></div></div>`;
        const btn = host.querySelector(".dd-btn");
        const pop = host.querySelector(".dd-pop");
        const val = host.querySelector(".dd-val");

        function selectedSet() {
            return state[stateKey];
        }

        function renderPop() {
            const sel = selectedSet();
            const allChecked = sel === null;
            pop.innerHTML =
                `<label class="dd-all"><input type="checkbox" data-all ${allChecked ? "checked" : ""}/>All</label>` +
                options
                    .map(
                        (opt) =>
                            `<label><input type="checkbox" data-v="${escAttr(opt)}" ${allChecked || sel.has(opt) ? "checked" : ""
                            }/>${esc(opt)}</label>`
                    )
                    .join("");
            pop.querySelector("[data-all]").addEventListener("change", (e) => {
                state[stateKey] = e.target.checked ? null : new Set();
                onFilterChanged(stateKey);
                renderPop();
                renderVal();
            });
            pop.querySelectorAll("input[data-v]").forEach((cb) =>
                cb.addEventListener("change", () => {
                    const chosen = new Set(
                        Array.from(pop.querySelectorAll("input[data-v]"))
                            .filter((c) => c.checked)
                            .map((c) => c.dataset.v)
                    );
                    state[stateKey] = chosen.size === options.length ? null : chosen;
                    onFilterChanged(stateKey);
                    renderPop();
                    renderVal();
                })
            );
        }

        function renderVal() {
            const sel = selectedSet();
            if (sel === null) val.textContent = "All";
            else if (sel.size === 0) val.textContent = "None";
            else if (sel.size <= 2) val.textContent = Array.from(sel).join(", ");
            else val.textContent = sel.size + " selected";
        }

        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            closeAllPops(pop);
            pop.classList.toggle("hidden");
        });
        pop.addEventListener("click", (e) => e.stopPropagation());

        host._refreshOptions = (newOptions) => {
            options = newOptions;
            // Drop selections that no longer exist.
            const sel = selectedSet();
            if (sel !== null) {
                const kept = new Set(Array.from(sel).filter((v) => options.includes(v)));
                state[stateKey] = kept.size === 0 ? null : kept;
            }
            renderPop();
            renderVal();
        };

        renderPop();
        renderVal();
    }

    function buildLinkedIdentitySelect() {
        const host = document.getElementById("fltLinkedIdentity");
        host.innerHTML =
            `<label>Linked Identity</label>` +
            `<div class="dd"><button class="dd-btn" type="button">` +
            `<span class="dd-val">All</span><span class="dd-caret">&#9660;</span></button>` +
            `<div class="dd-pop hidden"></div></div>`;
        const btn = host.querySelector(".dd-btn");
        const pop = host.querySelector(".dd-pop");
        const val = host.querySelector(".dd-val");

        function renderPop() {
            const opts =
                `<label class="dd-all"><input type="radio" name="li" data-v="" ${!state.linkedIdentity ? "checked" : ""
                }/>All</label>` +
                (linkedIdentityOptions.length
                    ? linkedIdentityOptions
                        .map(
                            (o) =>
                                `<label><input type="radio" name="li" data-v="${escAttr(o.id)}" ${state.linkedIdentity === o.id ? "checked" : ""
                                }/>${esc(o.label)}</label>`
                        )
                        .join("")
                    : `<div class="muted" style="padding:5px 8px;">No linked identities in this export</div>`);
            pop.innerHTML = opts;
            pop.querySelectorAll("input[data-v]").forEach((r) =>
                r.addEventListener("change", () => {
                    state.linkedIdentity = r.dataset.v;
                    val.textContent = state.linkedIdentity
                        ? displayNameForId(state.linkedIdentity)
                        : "All";
                    pop.classList.add("hidden");
                    resetSelection();
                    resetPagination();
                    render();
                })
            );
        }

        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            closeAllPops(pop);
            pop.classList.toggle("hidden");
        });
        pop.addEventListener("click", (e) => e.stopPropagation());
        renderPop();
    }

    function closeAllPops(except) {
        document.querySelectorAll(".dd-pop").forEach((p) => {
            if (p !== except) p.classList.add("hidden");
        });
    }
    document.addEventListener("click", () => closeAllPops());

    function onFilterChanged(stateKey) {
        if (stateKey === "roleSystems" || stateKey === "tierLevels") {
            const svcHost = document.getElementById("fltService");
            if (svcHost._refreshOptions) svcHost._refreshOptions(serviceOptions());
        }
        resetSelection();
        resetPagination();
        render();
    }

    // ---- Exported-parameter chips ----------------------------------------------
    const EXPORTS = [
        ["syncSource", "Sync source"],
        ["restrictedManagement", "Restricted management"],
        ["assignmentType", "Assignment type"],
        ["objectTier", "Identity classification"],
        ["accessTier", "Access classification"],
    ];

    function toggleExport(key, value) {
        state[key] = state[key] === value ? "*" : value;
        resetSelection();
        resetPagination();
        render();
    }

    function resetSelection() {
        state.selectedObjectId = "*";
        state.selectedAssignmentIds.clear();
    }

    // Rows displayed per grid always reset to the default page size whenever the
    // filtered result set can change shape (filters, search, exported-parameter
    // clicks). Without this, clicking "Show all" once on a large table (thousands
    // of rows) leaves state.limits.* stuck at that huge count - so the NEXT filter
    // change re-renders every one of those rows again on top of the other seven
    // render functions, which at large scale (~8k+ rows) can block the main thread
    // for 30+ seconds. See Privileged EAM Reporting load-test notes.
    function resetPagination() {
        state.limits.asset = 50;
        state.limits.assignment = 50;
        state.limits.classification = 50;
    }

    function renderExportChips() {
        const host = document.getElementById("activeExports");
        const active = EXPORTS.filter(([k]) => state[k] !== "*");
        const chips = active.map(
            ([k, lbl]) =>
                `<span class="chip brand">${esc(lbl)}: ${esc(k === "objectTier" ? String(state[k]).split(",").map((t) => TIER_TEXT[t] || t).join(", ") : state[k])}<span class="chip-x" data-k="${k}">&#10005;</span></span>`
        );
        if (state.selectedObjectId !== "*") {
            chips.push(
                `<span class="chip warn">Selected asset: ${esc(displayNameForId(state.selectedObjectId))}<span class="chip-x" data-k="selectedObjectId">&#10005;</span></span>`
            );
        }
        if (chips.length === 0) {
            host.classList.add("hidden");
            host.innerHTML = "";
            return;
        }
        host.classList.remove("hidden");
        host.innerHTML = `<span class="lbl">Active selections</span>` + chips.join("");
        host.querySelectorAll(".chip-x").forEach((x) =>
            x.addEventListener("click", () => {
                const k = x.dataset.k;
                if (k === "selectedObjectId") resetSelection();
                else {
                    state[k] = "*";
                    resetSelection();
                }
                resetPagination();
                render();
            })
        );
    }

    // ---- Overview visualizations -------------------------------------------------
    function renderSyncTiles() {
        // Workbook "Sync source of privileged identities" (tiles, zero-filled).
        const objs = dedupeById(baseRecords());
        const counts = { "Cloud-Only": 0, Hybrid: 0 };
        objs.forEach((o) => (counts[o.syncSource] = (counts[o.syncSource] || 0) + 1));
        const host = document.getElementById("syncTiles");
        host.innerHTML = ["Cloud-Only", "Hybrid"]
            .map(
                (k) =>
                    `<div class="eam-tile ${state.syncSource === k ? "selected" : ""}" data-v="${escAttr(k)}">` +
                    `<div class="t-label"><span class="t-dot" style="background:${k === "Hybrid" ? "#5c2d91" : "#0078d4"}"></span>${esc(k)}</div>` +
                    `<div class="t-value">${(counts[k] || 0).toLocaleString()}</div></div>`
            )
            .join("");
        host.querySelectorAll(".eam-tile").forEach((t) =>
            t.addEventListener("click", () => toggleExport("syncSource", t.dataset.v))
        );
    }

    function renderRestrictedPie() {
        // Workbook "Restricted management of privileged identities" (pie by distinct object).
        const objs = dedupeById(baseRecords());
        const counts = new Map();
        objs.forEach((o) => counts.set(o.restrictedManagement, (counts.get(o.restrictedManagement) || 0) + 1));
        const order = ["Applied", "Conflict", "Not applied", "Not available"];
        const colors = {
            Applied: "#0e700e",
            Conflict: "#c07807",
            "Not applied": "#a4262c",
            "Not available": "#8a8886",
        };
        const segs = order
            .filter((k) => counts.get(k))
            .map((k) => ({ key: k, value: counts.get(k), color: colors[k] }));
        renderDonut("restrictedPie", segs, "restrictedManagement");
    }

    function renderAssignmentPie() {
        // Workbook "Assignments of privileged roles":
        // count all role assignments of matching objects by RoleAssignmentType + PIMAssignmentType.
        const objs = baseRecords().filter(syncSourceMatch);
        const counts = new Map();
        objs.forEach((o) =>
            (o.roleAssignments || []).forEach((ra) => {
                const k = assignmentTypeOf(ra) || "(unknown)";
                counts.set(k, (counts.get(k) || 0) + 1);
            })
        );
        const segs = Array.from(counts.entries())
            .sort((a, b) => b[1] - a[1])
            .map(([key, value], i) => ({ key, value, color: PIE_PALETTE[i % PIE_PALETTE.length] }));
        renderDonut("assignmentPie", segs, "assignmentType");
    }

    function renderDonut(hostId, segs, exportKey) {
        const host = document.getElementById(hostId);
        const total = segs.reduce((s, d) => s + d.value, 0);
        if (total === 0) {
            host.innerHTML = `<div class="empty" style="flex:1;">No data matches the current filters.</div>`;
            return;
        }
        const size = 150, r = 65, ir = 40, cx = size / 2, cy = size / 2;
        let a0 = -Math.PI / 2;
        const paths = segs
            .map((d) => {
                const a1 = a0 + (d.value / total) * Math.PI * 2;
                const p = donutArc(cx, cy, r, ir, a0, a1);
                a0 = a1;
                const selected = state[exportKey] === d.key;
                return `<path class="donut-seg ${state[exportKey] !== "*" && !selected ? "dim" : ""}" d="${p}" fill="${d.color}" data-v="${escAttr(d.key)}"><title>${esc(d.key)}: ${d.value.toLocaleString()}</title></path>`;
            })
            .join("");
        const legend = segs
            .map(
                (d) =>
                    `<div class="li ${state[exportKey] === d.key ? "selected" : ""}" data-v="${escAttr(d.key)}">` +
                    `<span class="sw" style="background:${d.color}"></span><span class="nm">${esc(d.key)}</span>` +
                    `<span class="n">${d.value.toLocaleString()}</span></div>`
            )
            .join("");
        host.innerHTML =
            `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">` +
            paths +
            `<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central" font-size="20" font-weight="600" fill="var(--neutral-fg)">${total.toLocaleString()}</text>` +
            `</svg><div class="donut-legend">${legend}</div>`;
        host.querySelectorAll("[data-v]").forEach((el) =>
            el.addEventListener("click", () => toggleExport(exportKey, el.dataset.v))
        );
    }

    function donutArc(cx, cy, r, ir, a0, a1) {
        // Avoid a full-circle arc collapsing to nothing.
        if (a1 - a0 >= Math.PI * 2 - 1e-4) a1 = a0 + Math.PI * 2 - 1e-4;
        const large = a1 - a0 > Math.PI ? 1 : 0;
        const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
        const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
        const xi0 = cx + ir * Math.cos(a1), yi0 = cy + ir * Math.sin(a1);
        const xi1 = cx + ir * Math.cos(a0), yi1 = cy + ir * Math.sin(a0);
        return (
            `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} ` +
            `L ${xi0} ${yi0} A ${ir} ${ir} 0 ${large} 0 ${xi1} ${yi1} Z`
        );
    }

    function renderObjectTierTiles() {
        // Workbook "Classification of privileged identities":
        // distinct non-group objects by ObjectAdminTierLevelName (zero-filled).
        const objs = dedupeById(
            baseRecords().filter((o) => o.objectType !== "group" && syncSourceMatch(o))
        );
        const counts = new Map();
        objs.forEach((o) =>
            counts.set(o.objectAdminTierLevelName, (counts.get(o.objectAdminTierLevelName) || 0) + 1)
        );
        renderTierTiles("objectTierTiles", counts, "objectTier");
    }

    function renderAccessTierTiles() {
        // Workbook "Classification of privileged access":
        // distinct (ObjectId, classification tier) pairs, filtered by identity classification.
        const objs = baseRecords().filter((o) => syncSourceMatch(o) && objectTierMatch(o));
        const pairSeen = new Set();
        const counts = new Map();
        objs.forEach((o) =>
            (o.classification || []).forEach((c) => {
                const key = o.objectId + "|" + c.adminTierLevelName;
                if (pairSeen.has(key)) return;
                pairSeen.add(key);
                counts.set(c.adminTierLevelName, (counts.get(c.adminTierLevelName) || 0) + 1);
            })
        );
        renderTierTiles("accessTierTiles", counts, "accessTier");
    }

    function renderTierTiles(hostId, counts, exportKey) {
        const host = document.getElementById(hostId);
        host.innerHTML = TIER_ORDER.map(
            (t) =>
                `<div class="eam-tile ${state[exportKey] === t ? "selected" : ""}" data-v="${escAttr(t)}">` +
                `<div class="t-label"><span class="t-dot" style="background:${TIER_COLOR[t]}"></span>${esc(TIER_TEXT[t])}</div>` +
                `<div class="t-value" style="color:${TIER_COLOR[t]}">${(counts.get(t) || 0).toLocaleString()}</div></div>`
        ).join("");
        host.querySelectorAll(".eam-tile").forEach((t) =>
            t.addEventListener("click", () => toggleExport(exportKey, t.dataset.v))
        );
    }

    // ---- List of Privileged Assets --------------------------------------------
    let currentAssets = [];

    function buildAssets() {
        if (renderCache.assets) return renderCache.assets;
        // Workbook: summarize RoleSystem = make_set(RoleSystem) by object columns.
        const map = new Map();
        assetRecords().forEach((o) => {
            let row = map.get(o.objectId);
            if (!row) {
                row = {
                    objectId: o.objectId,
                    objectTenantId: o.objectTenantId,
                    objectType: o.objectType,
                    objectSubType: o.objectSubType,
                    objectDisplayName: o.objectDisplayName,
                    objectUserPrincipalName: o.objectUserPrincipalName,
                    objectAdminTierLevelName: o.objectAdminTierLevelName,
                    syncSource: o.syncSource,
                    restrictedManagement: o.restrictedManagement,
                    restricted: {
                        RestrictedManagementByAadRole: o.restrictedManagementByAadRole,
                        RestrictedManagementByRAG: o.restrictedManagementByRAG,
                        RestrictedManagementByRMAU: o.restrictedManagementByRMAU,
                    },
                    adminUnits: asArray(o.assignedAdministrativeUnits),
                    linkedIdentity: asArray(o.associatedWorkAccount),
                    privilegedType: privilegedTypeOf(o),
                    outsideOfHomeTenant: !!o.outsideOfHomeTenant,
                    originType: o.originType || "",
                    originTenantId: o.originTenantId || "",
                    originId: o.originId || "",
                    objClassification: new Map(), // tier|service -> object-level classification entry
                    controlPlaneReasoning: new Map(),
                    assignmentEvidence: new Map(),
                    assignmentCount: 0,
                    roleSystems: new Set(),
                    _sortName: (o.objectDisplayName || "").toLowerCase(),
                };
                map.set(o.objectId, row);
            }
            row.roleSystems.add(o.roleSystem);
            row.assignmentCount += asArray(o.roleAssignments).length;
            (o.classification || []).forEach((c) => {
                const k = (c.adminTierLevelName || "Unclassified") + "|" + (c.service || "");
                if (!row.objClassification.has(k)) row.objClassification.set(k, c);
            });
            asArray(o.controlPlaneReasoning).forEach((reasoning) => {
                const key = reasoningKey(reasoning);
                if (!row.controlPlaneReasoning.has(key)) row.controlPlaneReasoning.set(key, reasoning);
            });
            asArray(o.roleAssignments).forEach((assignment) => {
                const key = [
                    o.roleSystem,
                    assignmentKey(assignment),
                    assignment.roleDefinitionId,
                    assignment.roleAssignmentScopeId,
                ].join("|");
                if (!row.assignmentEvidence.has(key)) {
                    row.assignmentEvidence.set(key, {
                        roleSystem: o.roleSystem,
                        roleAssignmentInstanceId: assignmentKey(assignment),
                        roleAssignmentId: assignment.roleAssignmentId,
                        roleDefinitionName: assignment.roleDefinitionName,
                        roleDefinitionId: assignment.roleDefinitionId,
                        roleAssignmentScopeName: assignment.roleAssignmentScopeName,
                        roleAssignmentScopeId: assignment.roleAssignmentScopeId,
                        roleAssignmentCondition: assignment.roleAssignmentCondition,
                        roleAssignmentConditionVersion: assignment.roleAssignmentConditionVersion,
                        roleDefinitionConditions: asArray(assignment.roleDefinitionConditions),
                        conditionEvaluation: assignment.conditionEvaluation || null,
                        classification: new Map(),
                        scopeReasoning: asArray(assignment.scopeReasoning),
                    });
                }
                const evidence = row.assignmentEvidence.get(key);
                asArray(assignment.classification).forEach((classification) => {
                    const classificationKey = [
                        classification.adminTierLevelName,
                        classification.service,
                        classification.taggedBy,
                        classification.taggedByRoleSystem,
                        asArray(classification.taggedByObjectIds).join(","),
                        asArray(classification.matchedActions).join(","),
                        asArray(classification.scopedObjects).map((obj) => `${obj.id}|${obj.displayName}`).join(","),
                    ].join("|");
                    if (!evidence.classification.has(classificationKey)) {
                        evidence.classification.set(classificationKey, classification);
                    }
                });
            });
        });
        renderCache.assets = Array.from(map.values()).sort((a, b) => cmpStr(a._sortName, b._sortName));
        return renderCache.assets;
    }

    function renderPager(hostId, limitKey, total, rerender) {
        const host = document.getElementById(hostId);
        if (total <= state.limits[limitKey]) {
            host.classList.add("hidden");
            host.innerHTML = "";
            return;
        }
        host.classList.remove("hidden");
        host.innerHTML =
            `<span>Showing ${Math.min(state.limits[limitKey], total).toLocaleString()} of ${total.toLocaleString()} row(s)</span>` +
            `<button class="btn small" data-more>Show ${Math.min(PAGE_STEP, total - state.limits[limitKey]).toLocaleString()} more</button>` +
            `<button class="btn small" data-all>Show all</button>`;
        host.querySelector("[data-more]").addEventListener("click", () => {
            state.limits[limitKey] += PAGE_STEP;
            rerender();
        });
        host.querySelector("[data-all]").addEventListener("click", () => {
            state.limits[limitKey] = total;
            rerender();
        });
    }

    function renderAssetTable() {
        // Sort the FULL filtered set before pagination slicing, so a sort
        // covers all rows and not just the currently visible page.
        const allRows = applySort(buildAssets(), "asset");
        currentAssets = allRows;
        document.getElementById("assetCount").textContent = allRows.length + " asset(s)";
        document.getElementById("cnt-assets").textContent = allRows.length.toLocaleString();
        const rows = allRows.slice(0, state.limits.asset);
        renderPager("assetPager", "asset", allRows.length, renderAssetTable);

        updateCompareUi();

        const selChip = document.getElementById("assetSelChip");
        const selClear = document.getElementById("assetSelClear");
        if (state.selectedObjectId !== "*") {
            selChip.textContent = "Selected: " + displayNameForId(state.selectedObjectId);
            selChip.classList.remove("hidden");
            selClear.classList.remove("hidden");
        } else {
            selChip.classList.add("hidden");
            selClear.classList.add("hidden");
        }

        const tbody = document.querySelector("#assetTable tbody");
        const reviewIds = window.EOReview ? EOReview.idsSet() : new Set();
        tbody.innerHTML = rows
            .map((r, i) => {
                const typeIco = TYPE_ICON[r.objectType] || TYPE_ICON.unknown;
                const rmIco = RM_ICON[r.restrictedManagement] || RM_ICON["Not available"];
                const typeLabel = typeIco[1];
                const subTypeLabel = r.objectSubType || "—";
                const restrictedManagementLabel = rmIco[1];
                const auCell = r.adminUnits.length
                    ? `<span class="cell-link" data-au="${i}">${r.adminUnits.length} unit(s)</span>`
                    : `<span class="muted">&mdash;</span>`;
                const liCell = r.linkedIdentity.length
                    ? `<span class="linked-identity-list">${r.linkedIdentity.map((id) => {
                        const displayName = displayNameForId(id);
                        const href = "https://security.microsoft.com/user?aad=" + encodeURIComponent(id) + "&tid=" + encodeURIComponent(r.objectTenantId || "");
                        return `<a class="cell-link cell-truncate linked-identity-link" href="${escAttr(href)}" target="_blank" rel="noopener noreferrer" title="${escAttr(displayName + " (" + id + ")")}" aria-label="Open linked identity ${escAttr(displayName)} in Microsoft Defender">${esc(displayName)}</a>`;
                    }).join("")}</span>`
                    : `<span class="muted">&mdash;</span>`;
                const systemNames = Array.from(r.roleSystems).sort();
                const sys = Array.from(r.roleSystems)
                    .sort()
                    .map((s) => {
                        const ico = SYSTEM_ICON[s] || ["&#10067;", s];
                        return `<span class="ico-cell" title="${escAttr(ico[1])}" style="margin-right:8px;"><span class="ico-glyph">${ico[0]}</span>${esc(s)}</span>`;
                    })
                    .join("");
                const cmpChecked = state.compareIds.has(r.objectId);
                const starId = principalReviewId(r.objectId);
                const starCell = window.EOReview
                    ? EOReview.starHtml(starId, undefined, reviewIds.has(starId)).replace("<button ", `<button data-eo-id="${escAttr(starId)}" data-star="${i}" `)
                    : "";
                return (
                    `<tr class="asset-row ${state.selectedObjectId === r.objectId ? "sel-row" : ""}${cmpChecked ? " cmp-row" : ""}" data-id="${escAttr(r.objectId)}" data-i="${i}">` +
                    `<td class="col-icon"><input type="checkbox" data-cmp="${i}" title="Select for comparison" ${cmpChecked ? "checked" : ""}/></td>` +
                    `<td title="${escAttr(typeLabel)}"><span class="ico-cell asset-type"><span class="ico-glyph">${typeIco[0]}</span><span class="cell-truncate">${esc(typeLabel)}</span></span></td>` +
                    `<td title="${escAttr(subTypeLabel)}"><span class="cell-truncate">${esc(subTypeLabel)}</span></td>` +
                    `<td class="cell-strong" title="${escAttr(r.objectUserPrincipalName || r.objectDisplayName || "")}"><span class="cell-truncate">${esc(r.objectDisplayName)}</span></td>` +
                    `<td>${tierBadge(r.objectAdminTierLevelName)}</td>` +
                    `<td title="${escAttr(restrictedManagementLabel)}"><span class="cell-link ico-cell" data-rm="${i}"><span class="ico-glyph">${rmIco[0]}</span><span class="cell-truncate">${esc(restrictedManagementLabel)}</span></span></td>` +
                    `<td title="${escAttr(r.syncSource)}"><span class="cell-truncate">${esc(r.syncSource)}</span></td>` +
                    `<td class="asset-admin-units">${auCell}</td>` +
                    `<td class="asset-linked-identity">${liCell}</td>` +
                    `<td title="${escAttr(systemNames.join(", "))}"><span class="asset-system-list">${sys}</span></td>` +
                    `<td class="cell-mono" title="${escAttr(r.objectId)}"><span class="cell-truncate">${esc(r.objectId)}</span></td>` +
                    `<td class="cell-mono asset-tenant-id" title="${escAttr(r.objectTenantId || "")}">${r.objectTenantId ? `<span class="cell-truncate">${esc(r.objectTenantId)}</span>` : `<span class="muted">&mdash;</span>`}</td>` +
                    `<td class="col-icon">${starCell}</td>` +
                    `<td class="col-icon"><button type="button" class="detail-btn${Array.from(r.assignmentEvidence.values()).some((assignment) => assignment.scopeReasoning.length) ? " detail-btn-scope" : ""}" data-cls="${i}" title="Show classification reasoning and scope details" aria-label="Show classification reasoning and scope details for ${escAttr(r.objectDisplayName)}">&#9432;</button></td>` +
                    `<td class="col-icon"><button type="button" class="detail-btn" data-det="${i}" title="Show all asset details">&#187;</button></td>` +
                    `</tr>`
                );
            })
            .join("") || `<tr><td colspan="15"><div class="empty">No privileged assets match the current filters.</div></td></tr>`;

        tbody.querySelectorAll("tr.asset-row").forEach((tr) =>
            tr.addEventListener("click", (ev) => {
                // The compare checkbox and review star have their own handlers.
                if (ev.target.closest("[data-cmp],[data-star],[data-cls],[data-det]")) return;
                const id = tr.dataset.id;
                state.selectedObjectId = state.selectedObjectId === id ? "*" : id;
                state.selectedAssignmentIds.clear();
                render();
                if (state.selectedObjectId !== "*") {
                    scrollToSection("secAssignments");
                }
            })
        );
        // Comparison checkboxes (no full re-render: keep scroll position).
        tbody.querySelectorAll("input[data-cmp]").forEach((cb) =>
            cb.addEventListener("change", () => {
                const r = rows[Number(cb.dataset.cmp)];
                if (cb.checked) state.compareIds.add(r.objectId);
                else state.compareIds.delete(r.objectId);
                cb.closest("tr").classList.toggle("cmp-row", cb.checked);
                updateCompareUi();
            })
        );
        // Review-list stars (principal incl. its tier + systems).
        tbody.querySelectorAll("[data-star]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const r = rows[Number(btn.dataset.star)];
                const on = EOReview.toggle({
                    id: principalReviewId(r.objectId),
                    kind: "Principal",
                    system: Array.from(r.roleSystems).sort().join(", "),
                    name: r.objectDisplayName,
                    scope: r.objectUserPrincipalName || r.objectId,
                    tier: r.objectAdminTierLevelName,
                    hash: "#asset=" + encodeURIComponent(r.objectId),
                });
                EOReview.updateStar(btn, on);
            })
        );
        tbody.querySelectorAll("[data-cls]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                openAssetClassification(rows[Number(btn.dataset.cls)]);
            })
        );
        // Cell-detail context blades (workbook CellDetails link targets).
        tbody.querySelectorAll("[data-rm]").forEach((el) =>
            el.addEventListener("click", (e) => {
                e.stopPropagation();
                const r = rows[Number(el.dataset.rm)];
                openDrawer(
                    "Restricted management — " + r.objectDisplayName,
                    kvList([
                        ["Status", r.restrictedManagement],
                        ["Restricted by Entra ID role", yesNo(r.restricted.RestrictedManagementByAadRole)],
                        ["Restricted by Role-assignable Group", yesNo(r.restricted.RestrictedManagementByRAG)],
                        ["Restricted by RMAU", yesNo(r.restricted.RestrictedManagementByRMAU)],
                    ])
                );
            })
        );
        tbody.querySelectorAll("[data-au]").forEach((el) =>
            el.addEventListener("click", (e) => {
                e.stopPropagation();
                const r = rows[Number(el.dataset.au)];
                openDrawer(
                    "Administrative units — " + r.objectDisplayName,
                    // Entries can be plain id strings or {displayName, id} objects.
                    kvList(r.adminUnits.map((au) => (typeof au === "string" ? [au, au] : [au.displayName || au.id, au.id])))
                );
            })
        );
        // Full-context detail blade (&#8505; column).
        tbody.querySelectorAll("[data-det]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                openAssetDetails(rows[Number(btn.dataset.det)]);
            })
        );
    }

    document.getElementById("assetSelClear").addEventListener("click", () => {
        resetSelection();
        resetPagination();
        render();
    });

    // ---- Principal comparison ---------------------------------------------------
    // Compare role assignments and classified role actions of two or more privileged
    // principals (users, groups or service principals) side by side. Principals are
    // checked in the asset table or imported from the shared Review list; profiles
    // are built from the FULL dataset (independent of the active dashboard filters)
    // so a comparison always reflects the principal's complete privileged access.
    const CMP_MAX = 4;
    const cmpState = { diffOnly: true, q: "" };

    function principalReviewId(objectId) {
        return window.EOReview ? EOReview.makeId("principal", objectId) : "";
    }

    function updateCompareUi() {
        const btn = document.getElementById("assetCompareBtn");
        const n = state.compareIds.size;
        if (n >= 2) {
            btn.textContent = "\u21C4 Compare selected (" + n + ")";
            btn.classList.remove("hidden");
        } else if (n === 1) {
            btn.textContent = "\u21C4 Select one more to compare";
            btn.classList.remove("hidden");
            btn.disabled = true;
            return;
        } else {
            btn.classList.add("hidden");
        }
        btn.disabled = n < 2;
    }

    function buildPrincipalProfile(objectId) {
        const recs = DATA.objects.filter((o) => o.objectId === objectId);
        if (!recs.length) return null;
        const first = recs[0];
        const profile = {
            objectId,
            displayName: first.objectDisplayName,
            objectType: first.objectType,
            objectSubType: first.objectSubType,
            upn: first.objectUserPrincipalName,
            tier: first.objectAdminTierLevelName,
            syncSource: first.syncSource,
            restrictedManagement: first.restrictedManagement,
            systems: new Set(),
            assignments: new Map(), // system|role|scope -> row
            actions: new Map(),     // lowercased action -> { action, tier, services, scopes }
        };
        recs.forEach((o) => {
            profile.systems.add(o.roleSystem);
            (o.roleAssignments || []).forEach((ra) => {
                const scopeId = ra.roleAssignmentScopeId || ra.roleAssignmentScopeName || "";
                const key = [o.roleSystem, ra.roleDefinitionName, scopeId].join("|");
                let a = profile.assignments.get(key);
                if (!a) {
                    a = {
                        key,
                        roleSystem: o.roleSystem,
                        roleDefinitionName: ra.roleDefinitionName,
                        scopeId,
                        scopeName: ra.roleAssignmentScopeName || ra.roleAssignmentScopeId || "",
                        roleIsPrivileged: false,
                        types: new Set(),
                        pim: new Set(),
                        tiers: new Set(),
                    };
                    profile.assignments.set(key, a);
                }
                if (ra.roleAssignmentType) a.types.add(ra.roleAssignmentType);
                if (ra.pimAssignmentType) a.pim.add(ra.pimAssignmentType);
                if (ra.roleIsPrivileged) a.roleIsPrivileged = true;
                (ra.classification || []).forEach((c) => {
                    const t = c.adminTierLevelName || "Unclassified";
                    a.tiers.add(t);
                    asArray(c.matchedActions).forEach((act) => {
                        const alc = String(act).toLowerCase();
                        let e = profile.actions.get(alc);
                        if (!e) {
                            e = { action: act, tier: "Unclassified", services: new Set(), scopes: new Set() };
                            profile.actions.set(alc, e);
                        }
                        // Keep the highest-privilege tier this action was classified with.
                        if (TIER_ORDER.indexOf(t) !== -1 && TIER_ORDER.indexOf(t) < TIER_ORDER.indexOf(e.tier)) e.tier = t;
                        if (c.service) e.services.add(c.service);
                        if (a.scopeName) e.scopes.add(a.scopeName);
                    });
                });
            });
        });
        return profile;
    }

    function highestTierOf(tierSet) {
        let best = "Unclassified";
        tierSet.forEach((t) => {
            if (TIER_ORDER.indexOf(t) !== -1 && TIER_ORDER.indexOf(t) < TIER_ORDER.indexOf(best)) best = t;
        });
        return best;
    }

    // Hash that was active before the compare modal claimed it (e.g. an
    // #asset=/#assignment= deep link), restored on close so the modal doesn't
    // clobber it or leave a bare "#" behind.
    let cmpPrevHash = null;
    let cmpReturnFocus = null; // element focused before the modal opened

    function openCompareModal() {
        renderCompareModal();
        const modal = document.getElementById("cmpModal");
        if (!modal.classList.contains("open")) cmpReturnFocus = document.activeElement;
        modal.classList.add("open");
        document.getElementById("cmpBackdrop").classList.add("open");
        if ((location.hash || "").indexOf("#compare=") !== 0) cmpPrevHash = location.hash || "";
        history.replaceState(null, "", "#compare=" + Array.from(state.compareIds).map(encodeURIComponent).join(","));
        modal.focus();
    }

    function closeCompareModal() {
        const modal = document.getElementById("cmpModal");
        const wasOpen = modal.classList.contains("open");
        modal.classList.remove("open");
        document.getElementById("cmpBackdrop").classList.remove("open");
        if ((location.hash || "").indexOf("#compare=") === 0) {
            history.replaceState(null, "", cmpPrevHash || location.pathname + location.search);
        }
        cmpPrevHash = null;
        if (wasOpen && cmpReturnFocus && typeof cmpReturnFocus.focus === "function") {
            cmpReturnFocus.focus();
        }
        cmpReturnFocus = null;
    }

    function removeFromCompare(objectId) {
        state.compareIds.delete(objectId);
        renderAssetTable();
        if (state.compareIds.size >= 2) openCompareModal();
        else closeCompareModal();
    }

    // Review-list principals (kind 'Principal') that resolve to a dataset object
    // and are not part of the comparison yet.
    function reviewPrincipalCandidates() {
        if (!window.EOReview) return [];
        const out = [];
        const seen = new Set();
        EOReview.all().forEach((item) => {
            if (item.kind !== "Principal") return;
            const objectId = String(item.id || "").split("|")[1] || "";
            if (!objectId || state.compareIds.has(objectId) || seen.has(objectId)) return;
            if (!DATA.objects.some((o) => o.objectId === objectId)) return;
            seen.add(objectId);
            out.push({ objectId, name: item.name || objectId });
        });
        return out;
    }

    function renderCompareModal() {
        const profiles = Array.from(state.compareIds)
            .slice(0, CMP_MAX)
            .map(buildPrincipalProfile)
            .filter(Boolean);
        const body = document.getElementById("cmpBody");
        if (profiles.length < 2) {
            body.innerHTML = `<div class="empty" style="padding:32px;">Select at least two principals in the asset table to compare their privileged access.</div>`;
            return;
        }

        // ---- Union of role assignments -------------------------------------
        const assignUnion = new Map();
        profiles.forEach((p, i) => {
            p.assignments.forEach((a, key) => {
                let u = assignUnion.get(key);
                if (!u) {
                    u = { row: a, have: [] };
                    assignUnion.set(key, u);
                }
                u.have[i] = a;
                // Merge tier info (highest wins for the row badge).
                a.tiers.forEach((t) => u.row.tiers.add(t));
            });
        });
        const assignKeys = Array.from(assignUnion.keys()).sort((x, y) => {
            const a = assignUnion.get(x).row, b = assignUnion.get(y).row;
            const ta = TIER_ORDER.indexOf(highestTierOf(a.tiers)), tb = TIER_ORDER.indexOf(highestTierOf(b.tiers));
            return ta - tb || a.roleDefinitionName.localeCompare(b.roleDefinitionName) || a.scopeName.localeCompare(b.scopeName);
        });

        // ---- Union of classified role actions -------------------------------
        const actionUnion = new Map();
        profiles.forEach((p, i) => {
            p.actions.forEach((e, alc) => {
                let u = actionUnion.get(alc);
                if (!u) {
                    u = { action: e.action, tier: e.tier, services: new Set(), have: [] };
                    actionUnion.set(alc, u);
                }
                u.have[i] = e;
                if (TIER_ORDER.indexOf(e.tier) < TIER_ORDER.indexOf(u.tier)) u.tier = e.tier;
                e.services.forEach((s) => u.services.add(s));
            });
        });

        // ---- Per-principal stats --------------------------------------------
        const stats = profiles.map((p, i) => {
            let cp = 0, unique = 0;
            p.actions.forEach((e) => { if (e.tier === "ControlPlane") cp++; });
            actionUnion.forEach((u) => {
                if (!u.have[i]) return;
                let only = true;
                profiles.forEach((_, j) => { if (j !== i && u.have[j]) only = false; });
                if (only) unique++;
            });
            return { assignments: p.assignments.size, actions: p.actions.size, cp, unique };
        });

        // ---- Header: principal cards -----------------------------------------
        let html = `<div class="cmp-principals">`;
        profiles.forEach((p) => {
            const typeIco = TYPE_ICON[p.objectType] || TYPE_ICON.unknown;
            html +=
                `<div class="cmp-principal-card">` +
                `<div class="cmp-principal-name"><span class="ico-glyph">${typeIco[0]}</span>` +
                `<span class="cell-strong" title="${escAttr(p.upn || p.objectId)}">${esc(p.displayName)}</span>` +
                `<span class="chip-x" data-cmp-remove="${escAttr(p.objectId)}" title="Remove from comparison">&#10005;</span></div>` +
                `<div class="cmp-principal-meta">${tierBadge(p.tier)} <span class="muted">${esc(typeIco[1])}${p.objectSubType ? " \u00B7 " + esc(p.objectSubType) : ""} \u00B7 ${esc(p.syncSource)}</span></div>` +
                `<div class="cmp-principal-meta muted">${esc(Array.from(p.systems).sort().join(", "))}</div>` +
                `</div>`;
        });
        const candidates = reviewPrincipalCandidates();
        if (candidates.length && profiles.length < CMP_MAX) {
            html += `<div class="cmp-principal-card cmp-principal-add"><div class="cmp-principal-meta muted">&#9733; Add from Review list:</div>`;
            candidates.slice(0, 6).forEach((c) => {
                html += `<button type="button" class="chip cmp-add-chip" data-cmp-add="${escAttr(c.objectId)}">+ ${esc(c.name)}</button>`;
            });
            html += `</div>`;
        }
        html += `</div>`;

        // ---- Stats strip ------------------------------------------------------
        html += `<div class="cmp-stats"><table class="grid-table cmp-table"><thead><tr><th></th>`;
        profiles.forEach((p) => { html += `<th>${esc(p.displayName)}</th>`; });
        html += `</tr></thead><tbody>`;
        const statRows = [
            ["Role assignments", (s) => s.assignments.toLocaleString()],
            ["Classified role actions", (s) => s.actions.toLocaleString()],
            ["Control Plane actions", (s) => s.cp ? `<span class="cell-strong" style="color:${TIER_COLOR.ControlPlane}">${s.cp.toLocaleString()}</span>` : `<span class="muted">0</span>`],
            ["Actions no other selected principal has", (s) => s.unique ? `<span class="chip warn">${s.unique.toLocaleString()} unique</span>` : `<span class="muted">0</span>`],
        ];
        statRows.forEach(([lbl, fmt]) => {
            const vals = stats.map(fmt);
            const differs = vals.some((v) => v !== vals[0]);
            html += `<tr class="${differs ? "cmp-diff-row" : ""}"><td class="cmp-prop">${lbl}</td>${vals.map((v) => `<td>${v}</td>`).join("")}</tr>`;
        });
        html += `</tbody></table></div>`;

        // ---- Role assignments matrix -------------------------------------------
        html += `<div class="section-title" style="margin-top:18px;">Role assignments (${assignKeys.length})` +
            `<span class="hint" style="margin-left:10px;">highlighted rows are not shared by all selected principals</span></div>`;
        html += `<div class="cmp-matrix-wrap"><table class="grid-table cmp-table"><thead><tr><th>System</th><th>Role</th><th>Scope</th><th>Tier</th>`;
        profiles.forEach((p) => { html += `<th class="cmp-check-col" title="${escAttr(p.displayName)}">${esc(shortLabel(p.displayName))}</th>`; });
        html += `</tr></thead><tbody>`;
        if (!assignKeys.length) {
            html += `<tr><td colspan="${4 + profiles.length}"><div class="empty" style="padding:16px;">No role assignments found.</div></td></tr>`;
        }
        assignKeys.forEach((key) => {
            const u = assignUnion.get(key);
            const shared = profiles.every((_, i) => !!u.have[i]);
            const sysIco = SYSTEM_ICON[u.row.roleSystem] || ["&#10067;", u.row.roleSystem];
            html += `<tr class="${shared ? "" : "cmp-diff-row"}">` +
                `<td class="nowrap"><span class="ico-glyph">${sysIco[0]}</span> ${esc(u.row.roleSystem)}</td>` +
                `<td class="cell-strong">${esc(u.row.roleDefinitionName || "\u2014")}${u.row.roleIsPrivileged ? ' <span class="chip priv" title="Microsoft isPrivileged flag">privileged</span>' : ""}</td>` +
                `<td title="${escAttr(u.row.scopeId)}">${esc(u.row.scopeName || "\u2014")}</td>` +
                `<td>${tierBadge(highestTierOf(u.row.tiers))}</td>`;
            profiles.forEach((_, i) => {
                const a = u.have[i];
                if (!a) {
                    html += `<td class="cmp-check-col"><span class="cmp-no">&mdash;</span></td>`;
                } else {
                    const detail = Array.from(a.types).concat(Array.from(a.pim)).filter(Boolean).join(" \u00B7 ");
                    html += `<td class="cmp-check-col"><span class="cmp-yes" title="${escAttr(detail || "Assigned")}">&#10003;</span>` +
                        (detail ? `<div class="cmp-cell-detail">${esc(detail)}</div>` : "") + `</td>`;
                }
            });
            html += `</tr>`;
        });
        html += `</tbody></table></div>`;

        // ---- Role actions matrix --------------------------------------------------
        let commonCount = 0, diffCount = 0;
        actionUnion.forEach((u) => {
            if (profiles.every((_, i) => !!u.have[i])) commonCount++;
            else diffCount++;
        });
        html += `<div class="section-title" style="margin-top:18px;">Classified role actions` +
            ` <span class="chip brand">${commonCount.toLocaleString()} common</span>` +
            ` <span class="chip ${diffCount ? "warn" : ""}">${diffCount.toLocaleString()} different</span></div>` +
            `<div class="toolbar" style="margin:8px 0;">` +
            `<div class="search" style="max-width:340px;"><span class="search-ico">&#128269;</span>` +
            `<input type="text" id="cmpActionSearch" placeholder="Filter role actions&hellip;" value="${escAttr(cmpState.q)}"/></div>` +
            `<label class="chip" style="cursor:pointer;gap:6px;"><input type="checkbox" id="cmpDiffOnly" ${cmpState.diffOnly ? "checked" : ""}/> Differences only</label>` +
            `<span class="muted" id="cmpActionCount" style="font-size:12.5px;"></span></div>` +
            `<div class="cmp-matrix-wrap" id="cmpActionMatrix"></div>`;

        body.innerHTML = html;

        body.querySelectorAll("[data-cmp-remove]").forEach((x) =>
            x.addEventListener("click", () => removeFromCompare(x.getAttribute("data-cmp-remove")))
        );
        body.querySelectorAll("[data-cmp-add]").forEach((b) =>
            b.addEventListener("click", () => {
                state.compareIds.add(b.getAttribute("data-cmp-add"));
                renderAssetTable();
                openCompareModal();
            })
        );
        document.getElementById("cmpActionSearch").addEventListener("input", debounce((e) => {
            cmpState.q = e.target.value.trim().toLowerCase();
            renderCompareActionMatrix(profiles, actionUnion);
        }, 150));
        document.getElementById("cmpDiffOnly").addEventListener("change", (e) => {
            cmpState.diffOnly = e.target.checked;
            renderCompareActionMatrix(profiles, actionUnion);
        });

        renderCompareActionMatrix(profiles, actionUnion);
    }

    function renderCompareActionMatrix(profiles, actionUnion) {
        const host = document.getElementById("cmpActionMatrix");
        const LIMIT = 500;
        const keys = [];
        actionUnion.forEach((u, alc) => {
            const shared = profiles.every((_, i) => !!u.have[i]);
            if (cmpState.diffOnly && shared) return;
            if (cmpState.q && (u.action + " " + Array.from(u.services).join(" ")).toLowerCase().indexOf(cmpState.q) === -1) return;
            keys.push(alc);
        });
        keys.sort((a, b) => {
            const ua = actionUnion.get(a), ub = actionUnion.get(b);
            return TIER_ORDER.indexOf(ua.tier) - TIER_ORDER.indexOf(ub.tier) || (a < b ? -1 : 1);
        });

        let html = `<table class="grid-table cmp-table"><thead><tr><th>Role action</th><th class="nowrap">Tier</th><th>Service</th>`;
        profiles.forEach((p) => { html += `<th class="cmp-check-col" title="${escAttr(p.displayName)}">${esc(shortLabel(p.displayName))}</th>`; });
        html += `</tr></thead><tbody>`;
        if (!keys.length) {
            html += `<tr><td colspan="${3 + profiles.length}"><div class="empty" style="padding:16px;">` +
                (cmpState.diffOnly
                    ? "No differing role actions" + (cmpState.q ? " match the filter" : "") + " \u2014 the selected principals hold the same classified actions."
                    : "No role actions match the filter.") +
                `</div></td></tr>`;
        }
        keys.slice(0, LIMIT).forEach((alc) => {
            const u = actionUnion.get(alc);
            const shared = profiles.every((_, i) => !!u.have[i]);
            html += `<tr class="${shared ? "" : "cmp-diff-row"}">` +
                `<td><span class="cell-mono" style="font-size:12px;">${esc(u.action)}</span></td>` +
                `<td>${tierBadge(u.tier)}</td>` +
                `<td>${esc(Array.from(u.services).sort().join(", ") || "\u2014")}</td>`;
            profiles.forEach((_, i) => {
                const e = u.have[i];
                html += `<td class="cmp-check-col">` +
                    (e
                        ? `<span class="cmp-yes" title="${escAttr("Granted via scope(s): " + (Array.from(e.scopes).filter(Boolean).join(", ") || "\u2014"))}">&#10003;</span>`
                        : `<span class="cmp-no">&mdash;</span>`) +
                    `</td>`;
            });
            html += `</tr>`;
        });
        html += `</tbody></table>`;
        host.innerHTML = html;
        const meta = document.getElementById("cmpActionCount");
        if (meta) meta.textContent = keys.length.toLocaleString() + " action(s)" + (keys.length > LIMIT ? " (showing first " + LIMIT + ")" : "");
    }

    function shortLabel(name) {
        const s = String(name);
        return s.length > 20 ? s.slice(0, 19) + "\u2026" : s;
    }

    initializeGridColumnResizing();
    initializeGridSorting();

    function debounce(fn, wait) {
        let t;
        return function () {
            const args = arguments;
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), wait || 150);
        };
    }

    document.getElementById("assetCompareBtn").addEventListener("click", openCompareModal);
    document.getElementById("cmpClose").addEventListener("click", closeCompareModal);
    document.getElementById("cmpBackdrop").addEventListener("click", closeCompareModal);
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeCompareModal();
    });


    // ---- Related privileged role assignments -----------------------------------
    let currentAssignments = [];

    function buildAssignments() {
        if (renderCache.assignments) return renderCache.assignments;
        // Workbook: mv-expand RoleAssignments, mv-expand Classification,
        // summarize tier/service/taggedBy sets by assignment identity.
        const map = new Map();
        drillRecords().forEach((o) =>
            (o.roleAssignments || []).forEach((ra) => {
                const key = [
                    o.roleSystem, assignmentKey(ra), ra.roleDefinitionName, ra.roleType,
                    ra.roleAssignmentScopeId, ra.roleAssignmentScopeName, ra.pimAssignmentType,
                    ra.roleAssignmentType, ra.transitiveByObjectDisplayName, ra.roleAssignmentSubType,
                    asArray(ra.transitiveByNestingObjectDisplayNames).join("+"), ra.eligibilityBy,
                ].join("|");
                let row = map.get(key);
                if (!row) {
                    row = {
                        roleSystem: o.roleSystem,
                        roleAssignmentInstanceId: assignmentKey(ra),
                        roleAssignmentId: ra.roleAssignmentId,
                        roleDefinitionName: ra.roleDefinitionName,
                        roleDefinitionId: ra.roleDefinitionId,
                        roleType: ra.roleType,
                        roleIsPrivileged: false,
                        pimManagedRole: false,
                        roleAssignmentScopeId: ra.roleAssignmentScopeId,
                        roleAssignmentScopeName: ra.roleAssignmentScopeName || ra.roleAssignmentScopeId,
                        applicationScopes: asArray(ra.applicationScopes),
                        roleAssignmentCondition: ra.roleAssignmentCondition,
                        roleAssignmentConditionVersion: ra.roleAssignmentConditionVersion,
                        roleDefinitionConditions: asArray(ra.roleDefinitionConditions),
                        conditionEvaluation: ra.conditionEvaluation || null,
                        pimAssignmentType: ra.pimAssignmentType,
                        roleAssignmentType: ra.roleAssignmentType,
                        transitiveBy: ra.transitiveByObjectDisplayName,
                        transitiveByObjectId: ra.transitiveByObjectId,
                        transitiveByAssignment: ra.roleAssignmentSubType,
                        transitiveByNesting: asArray(ra.transitiveByNestingObjectDisplayNames),
                        eligibilityBy: ra.eligibilityBy,
                        scopeReasoning: ra.scopeReasoning || [],
                        tiers: new Set(),
                        services: new Set(),
                        taggedBy: new Set(),
                        principals: new Map(),  // objectId -> displayName (detail blade)
                        principalControlPlaneReasoning: new Map(),
                        classEntries: new Map(), // dedupe key -> full classification entry (detail blade)
                    };
                    map.set(key, row);
                }
                if (ra.roleIsPrivileged) row.roleIsPrivileged = true;
                if (ra.pimManagedRole) row.pimManagedRole = true;
                row.principals.set(o.objectId, o.objectDisplayName || o.objectId);
                asArray(o.controlPlaneReasoning).forEach((reasoning) => {
                    const principalReasoningKey = `${o.objectId}|${reasoningKey(reasoning)}`;
                    if (!row.principalControlPlaneReasoning.has(principalReasoningKey)) {
                        row.principalControlPlaneReasoning.set(principalReasoningKey, {
                            objectId: o.objectId,
                            displayName: o.objectDisplayName || o.objectId,
                            reasoning,
                        });
                    }
                });
                (ra.classification || []).forEach((c) => {
                    row.tiers.add(c.adminTierLevelName || "Unclassified");
                    if (c.service) row.services.add(c.service);
                    if (c.taggedBy) row.taggedBy.add(c.taggedBy);
                    const ck = [
                        c.adminTierLevelName, c.service, c.taggedBy, c.taggedByRoleSystem,
                        asArray(c.taggedByObjectDisplayNames).join(","), asArray(c.matchedActions).join(","),
                        asArray(c.scopedObjects).map((obj) => `${obj.id}|${obj.displayName}`).join(","),
                    ].join("|");
                    if (!row.classEntries.has(ck)) row.classEntries.set(ck, c);
                });
            })
        );
        const rows = Array.from(map.values());
        rows.forEach((r) => {
            const sorted = Array.from(r.tiers).sort(
                (a, b) => TIER_ORDER.indexOf(a) - TIER_ORDER.indexOf(b)
            );
            r.adminTierLevel = sorted.length ? sorted[0] : "Unclassified";
            r._sortScope = String(r.roleAssignmentScopeId).toLowerCase();
            r._sortRole = (r.roleDefinitionName || "").toLowerCase();
        });
        rows.sort(
            (a, b) =>
                cmpStr(a.adminTierLevel, b.adminTierLevel) ||
                cmpStr(a._sortScope, b._sortScope) ||
                cmpStr(a._sortRole, b._sortRole)
        );
        renderCache.assignments = rows;
        return renderCache.assignments;
    }

    function renderAssignmentTable() {
        // Sort the FULL filtered set before pagination slicing (see renderAssetTable).
        const allRows = applySort(buildAssignments(), "assignment");
        currentAssignments = allRows;
        // Drop selected assignment ids that are no longer visible.
        const visible = new Set(allRows.map((r) => r.roleAssignmentInstanceId));
        Array.from(state.selectedAssignmentIds).forEach((id) => {
            if (!visible.has(id)) state.selectedAssignmentIds.delete(id);
        });

        document.getElementById("assignmentCount").textContent = allRows.length + " assignment(s)";
        document.getElementById("cnt-assignments").textContent = allRows.length.toLocaleString();
        const rows = allRows.slice(0, state.limits.assignment);
        renderPager("assignmentPager", "assignment", allRows.length, renderAssignmentTable);

        const selChip = document.getElementById("assignmentSelChip");
        const selClear = document.getElementById("assignmentSelClear");
        if (state.selectedAssignmentIds.size > 0) {
            selChip.textContent = state.selectedAssignmentIds.size + " selected";
            selChip.classList.remove("hidden");
            selClear.classList.remove("hidden");
        } else {
            selChip.classList.add("hidden");
            selClear.classList.add("hidden");
        }

        const tbody = document.querySelector("#assignmentTable tbody");
        const reviewIds = window.EOReview ? EOReview.idsSet() : new Set();
        tbody.innerHTML = rows
            .map((r, i) => {
                const sysIco = SYSTEM_ICON[r.roleSystem] || ["&#10067;", r.roleSystem];
                const checked = state.selectedAssignmentIds.has(r.roleAssignmentInstanceId);
                const nesting = r.transitiveByNesting.length
                    ? `<span class="cell-link" data-nest="${i}">${r.transitiveByNesting.length} object(s)</span>`
                    : `<span class="muted">&mdash;</span>`;
                const services = Array.from(r.services).sort();
                const svcCell =
                    services.length === 0
                        ? `<span class="muted">&mdash;</span>`
                        : services.length === 1
                            ? `<span class="cell-truncate" title="${escAttr(services[0])}">${esc(services[0])}</span>`
                            : `<span class="cell-link" data-svc="${i}">${services.length} services</span>`;
                const starId = reviewIdFor(r);
                const starCell = window.EOReview
                    ? EOReview.starHtml(starId, undefined, reviewIds.has(starId)).replace("<button ", `<button data-eo-id="${escAttr(starId)}" data-star="${i}" `)
                    : "";
                return (
                    `<tr class="assign-row ${checked ? "sel-row" : ""}" data-i="${i}">` +
                    `<td class="col-icon"><input type="checkbox" data-sel="${i}" ${checked ? "checked" : ""}/></td>` +
                    `<td><span class="ico-cell assignment-system" title="${escAttr(sysIco[1])}"><span class="ico-glyph">${sysIco[0]}</span><span class="cell-truncate">${esc(sysIco[1])}</span></span></td>` +
                    `<td>${tierBadge(r.adminTierLevel)}</td>` +
                    `<td class="cell-strong"><span class="cell-truncate" title="${escAttr(r.roleDefinitionName || "—")}">${esc(r.roleDefinitionName || "—")}</span></td>` +
                    `<td><span class="cell-truncate" title="${escAttr(r.roleType || "—")}">${esc(r.roleType || "—")}</span></td>` +
                    `<td><span class="assignment-scope"><span class="cell-truncate" title="${escAttr(r.roleAssignmentScopeId || r.roleAssignmentScopeName || "")}">${esc(r.roleAssignmentScopeName || "—")}</span></span></td>` +
                    `<td><span class="cell-truncate" title="${escAttr(r.pimAssignmentType || "—")}">${esc(r.pimAssignmentType || "—")}</span></td>` +
                    `<td><span class="cell-truncate" title="${escAttr(r.roleAssignmentType || "—")}">${esc(r.roleAssignmentType || "—")}</span></td>` +
                    `<td><span class="cell-truncate" title="${escAttr(r.eligibilityBy || "N/A")}">${esc(r.eligibilityBy || "N/A")}</span></td>` +
                    `<td><span class="cell-truncate" title="${escAttr(r.transitiveBy || "—")}">${esc(r.transitiveBy || "—")}</span></td>` +
                    `<td><span class="cell-truncate" title="${escAttr(r.transitiveByAssignment || "—")}">${esc(r.transitiveByAssignment || "—")}</span></td>` +
                    `<td>${nesting}</td>` +
                    `<td>${svcCell}</td>` +
                    `<td class="col-icon">${starCell}</td>` +
                    `<td class="col-icon"><button type="button" class="detail-btn${asArray(r.scopeReasoning).length ? " detail-btn-scope" : ""}" data-cls="${i}" title="Show classification reasoning and scope details" aria-label="Show classification reasoning and scope details for ${escAttr(r.roleDefinitionName || "role assignment")}">&#9432;</button></td>` +
                    `<td class="col-icon"><button type="button" class="detail-btn" data-det="${i}" title="Show all assignment details">&#187;</button></td>` +
                    `</tr>`
                );
            })
            .join("") || `<tr><td colspan="16"><div class="empty">No role assignments match the current filters.</div></td></tr>`;

        tbody.querySelectorAll("input[data-sel]").forEach((cb) =>
            cb.addEventListener("change", () => {
                const r = rows[Number(cb.dataset.sel)];
                if (cb.checked) state.selectedAssignmentIds.add(r.roleAssignmentInstanceId);
                else state.selectedAssignmentIds.delete(r.roleAssignmentInstanceId);
                delete renderCache.classifications;
                renderAssignmentTable();
                renderClassificationTable();
            })
        );
        // Clicking anywhere on an assignment row toggles the same
        // RoleAssignmentInstanceId filter as its checkbox (workbook
        // SelectedRoleAssignmentIds export). The checkbox, cell links,
        // review star and » details button keep their own handlers.
        tbody.querySelectorAll("tr.assign-row").forEach((tr) =>
            tr.addEventListener("click", (ev) => {
                if (ev.target.closest("input,button,[data-nest],[data-svc]")) return;
                const r = rows[Number(tr.dataset.i)];
                if (state.selectedAssignmentIds.has(r.roleAssignmentInstanceId)) {
                    state.selectedAssignmentIds.delete(r.roleAssignmentInstanceId);
                } else {
                    state.selectedAssignmentIds.add(r.roleAssignmentInstanceId);
                }
                delete renderCache.classifications;
                renderAssignmentTable();
                renderClassificationTable();
                scrollToSection("secClassification");
            })
        );
        tbody.querySelectorAll("[data-nest]").forEach((el) =>
            el.addEventListener("click", (e) => {
                e.stopPropagation();
                const r = rows[Number(el.dataset.nest)];
                openDrawer(
                    "Transitive nesting — " + r.roleDefinitionName,
                    kvList(r.transitiveByNesting.map((n, idx) => ["Nesting level " + (idx + 1), n]))
                );
            })
        );
        tbody.querySelectorAll("[data-svc]").forEach((el) =>
            el.addEventListener("click", (e) => {
                e.stopPropagation();
                const r = rows[Number(el.dataset.svc)];
                openDrawer(
                    "Services — " + r.roleDefinitionName,
                    listPanel(Array.from(r.services).sort())
                );
            })
        );
        tbody.querySelectorAll("[data-cls]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                openAssignmentClassification(rows[Number(btn.dataset.cls)]);
            })
        );
        // Full-context detail blade (&#8505; column).
        tbody.querySelectorAll("[data-det]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                openAssignmentDetails(rows[Number(btn.dataset.det)]);
            })
        );
        tbody.querySelectorAll("[data-star]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const r = rows[Number(btn.dataset.star)];
                const on = EOReview.toggle({
                    id: reviewIdFor(r),
                    kind: "Role",
                    system: r.roleSystem,
                    name: r.roleDefinitionName,
                    scope: r.roleAssignmentScopeName || r.roleAssignmentScopeId || "",
                    tier: r.adminTierLevel,
                    hash: "#assignment=" + encodeURIComponent(r.roleAssignmentInstanceId),
                });
                EOReview.updateStar(btn, on);
            })
        );
    }

    function reviewIdFor(r) {
        return window.EOReview
            ? EOReview.makeId("role", r.roleSystem, r.roleAssignmentInstanceId, r.roleDefinitionName, r.roleAssignmentScopeId || r.roleAssignmentScopeName || "")
            : "";
    }

    // ---- Deep links (#assignment=<id> jumps back to a starred assignment,
    //      #asset=<id> jumps to a starred principal, #compare=<id,id,..> opens
    //      the principal comparison) --------------------------------------------
    // Resets every filter (like Tier Breach Analyzer), so a deep-linked asset or assignment that the current filters
    // hide is shown instead of reported as not found.
    function clearFiltersForDeepLink() {
        state.roleSystems = null;
        state.tierLevels = null;
        state.services = null;
        state.objectTypes = null;
        state.privilegedTypes = null;
        state.linkedIdentity = "";
        state.displayName = "";
        EXPORTS.forEach(([k]) => { state[k] = "*"; });
        resetSelection();
        const searchInput = document.getElementById("fltDisplayName");
        if (searchInput) searchInput.value = "";
        buildMultiSelect("fltRoleSystem", "RBAC System", allSystems, "roleSystems");
        buildMultiSelect("fltTierLevel", "RBAC Tier Level", allTiers, "tierLevels");
        buildMultiSelect("fltService", "Service", serviceOptions(), "services");
        buildMultiSelect("fltObjectType", "Principal Type", allTypes, "objectTypes");
        buildLinkedIdentitySelect();
        buildMultiSelect("fltPrivilegedType", "Privileged Type", PRIVILEGED_TYPES, "privilegedTypes");
        resetPagination();
        render();
    }

    function applyDeepLink() {
        const h = location.hash || "";
        let m = h.match(/^#asset=(.+)$/);
        if (m) {
            const wanted = decodeURIComponent(m[1]);
            const sameAsset = (r) => String(r.objectId).toLowerCase() === wanted.toLowerCase();
            let idx = currentAssets.findIndex(sameAsset);
            if (idx === -1 && DATA.objects.some(sameAsset)) {
                clearFiltersForDeepLink();
                idx = currentAssets.findIndex(sameAsset);
            }
            if (idx === -1) {
                if (window.EntraOpsReportUtils) {
                    EntraOpsReportUtils.deepLinkNotFound("Privileged asset", wanted, "Privileged EAM data");
                }
                return;
            }
            if (idx >= state.limits.asset) {
                state.limits.asset = idx + 25;
                renderAssetTable();
            }
            const tr = document.querySelector(`#assetTable tbody tr[data-id="${CSS.escape(currentAssets[idx].objectId)}"]`);
            if (!tr) return;
            tr.scrollIntoView({ behavior: "smooth", block: "center" });
            tr.classList.remove("eo-flash");
            void tr.offsetWidth; // restart the flash animation
            tr.classList.add("eo-flash");
            return;
        }
        m = h.match(/^#compare=(.+)$/);
        if (m) {
            const ids = decodeURIComponent(m[1]).split(",").filter((id) => DATA.objects.some((o) => o.objectId === id));
            if (ids.length >= 2) {
                state.compareIds = new Set(ids.slice(0, CMP_MAX));
                renderAssetTable();
                openCompareModal();
            }
            return;
        }
        m = h.match(/^#assignment=([^&]+)(?:&action=(.+))?$/);
        if (!m) return;
        const wanted = decodeURIComponent(m[1]);
        const wantedAction = m[2] ? decodeURIComponent(m[2]) : null;
        const sameAssignment = (r) => r.roleAssignmentInstanceId === wanted || r.roleAssignmentId === wanted;
        let idx = currentAssignments.findIndex(sameAssignment);
        if (idx === -1) {
            // Hidden by the filters? Clear them and look again.
            clearFiltersForDeepLink();
            idx = currentAssignments.findIndex(sameAssignment);
        }
        if (idx === -1) {
            if (window.EntraOpsReportUtils) EntraOpsReportUtils.deepLinkNotFound("Role assignment", wanted, "Privileged EAM data");
            return;
        }
        if (idx >= state.limits.assignment) {
            state.limits.assignment = idx + 25;
            renderAssignmentTable();
        }
        const tr = document.querySelectorAll("#assignmentTable tbody tr")[idx];
        if (!tr) return;
        tr.scrollIntoView({ behavior: "smooth", block: "center" });
        tr.classList.remove("eo-flash");
        void tr.offsetWidth; // restart the flash animation
        tr.classList.add("eo-flash");
        if (wantedAction) {
            openAssignmentClassification(currentAssignments[idx]);
            const button = Array.from(drawerBodyEl.querySelectorAll("[data-review-action]")).find((el) =>
                JSON.parse(el.dataset.reviewAction).name === wantedAction
            );
            if (button) {
                const details = button.closest("details");
                if (details) details.open = true;
                button.scrollIntoView({ behavior: "smooth", block: "center" });
                button.focus();
            } else if (window.EntraOpsReportUtils) {
                EntraOpsReportUtils.deepLinkNotFound("Role action", wantedAction, "assignment classification evidence");
            }
        }
    }

    document.getElementById("assignmentSelClear").addEventListener("click", () => {
        state.selectedAssignmentIds.clear();
        state.limits.classification = 50;
        delete renderCache.classifications;
        renderAssignmentTable();
        renderClassificationTable();
    });

    // ---- Related role classification ---------------------------------------------
    let currentClassifications = [];

    function buildClassifications() {
        if (renderCache.classifications) return renderCache.classifications;
        // Workbook: mv-expand Classification / TaggedByObjectDisplayNames (N/A when
        // empty), projected to the visible columns. Rows are aggregated by the
        // projection key; scope ids, matched actions, tagged-by object ids and the
        // holding principals are collected alongside for the detail blade without
        // changing the visible row granularity.
        const map = new Map();
        drillRecords().forEach((o) =>
            (o.roleAssignments || []).forEach((ra) => {
                if (
                    state.selectedAssignmentIds.size > 0 &&
                    !state.selectedAssignmentIds.has(assignmentKey(ra))
                ) {
                    return;
                }
                (ra.classification || []).forEach((c) => {
                    const names = asArray(c.taggedByObjectDisplayNames);
                    const ids = asArray(c.taggedByObjectIds);
                    const taggedNames = names.length > 0 ? names : ["N/A"];
                    taggedNames.forEach((tn, ni) => {
                        const scopeName = ra.roleAssignmentScopeName || ra.roleAssignmentScopeId;
                        const tier = c.adminTierLevelName || "Unclassified";
                        const key = [
                            o.roleSystem, scopeName, ra.roleDefinitionName, tier,
                            c.service, c.taggedBy, tn || "N/A", c.taggedByRoleSystem,
                        ].join("|");
                        let row = map.get(key);
                        if (!row) {
                            row = {
                                roleSystem: o.roleSystem,
                                roleAssignmentScopeName: scopeName,
                                roleDefinitionName: ra.roleDefinitionName,
                                adminTierLevel: tier,
                                service: c.service,
                                taggedBy: c.taggedBy,
                                taggedByObjectDisplayName: tn || "N/A",
                                taggedByRoleSystem: c.taggedByRoleSystem,
                                // Detail-blade context (not part of the projection key):
                                scopeIds: new Set(),
                                applicationScopes: new Set(),
                                taggedByObjectIds: new Set(),
                                matchedActions: new Set(),
                                scopedObjects: new Map(),
                                principals: new Map(), // objectId -> displayName
                                roleDefinitionIds: new Set(),
                                roleAssignmentIds: new Set(),
                                roleTypes: new Set(),
                                assignmentTypes: new Set(),
                                pimAssignmentTypes: new Set(),
                                eligibilityBy: new Set(),
                                assignmentConditions: new Set(),
                                assignmentConditionVersions: new Set(),
                                scopeReasoning: new Map(),
                                classificationEntries: new Map(),
                            };
                            map.set(key, row);
                        }
                        if (ra.roleAssignmentScopeId) row.scopeIds.add(ra.roleAssignmentScopeId);
                        asArray(ra.applicationScopes).forEach((scope) => row.applicationScopes.add(scope));
                        if (ra.roleDefinitionId) row.roleDefinitionIds.add(ra.roleDefinitionId);
                        if (ra.roleAssignmentId) row.roleAssignmentIds.add(ra.roleAssignmentId);
                        if (ra.roleType) row.roleTypes.add(ra.roleType);
                        if (ra.roleAssignmentType) row.assignmentTypes.add(ra.roleAssignmentType);
                        if (ra.pimAssignmentType) row.pimAssignmentTypes.add(ra.pimAssignmentType);
                        if (ra.eligibilityBy) row.eligibilityBy.add(ra.eligibilityBy);
                        if (ra.roleAssignmentCondition) row.assignmentConditions.add(ra.roleAssignmentCondition);
                        if (ra.roleAssignmentConditionVersion) row.assignmentConditionVersions.add(ra.roleAssignmentConditionVersion);
                        asArray(ra.scopeReasoning).forEach((reasoning) => {
                            row.scopeReasoning.set(reasoningKey(reasoning), reasoning);
                        });
                        if (names.length > 0 && ids[ni]) row.taggedByObjectIds.add(ids[ni]);
                        asArray(c.matchedActions).forEach((a) => row.matchedActions.add(String(a)));
                        asArray(c.scopedObjects).forEach((obj) => {
                            if (obj && (obj.id || obj.displayName)) row.scopedObjects.set(obj.id || obj.displayName, obj.displayName || obj.id);
                        });
                        const classificationKey = [
                            c.adminTierLevelName, c.service, c.taggedBy, c.taggedByRoleSystem,
                            asArray(c.taggedByObjectDisplayNames).join(","), asArray(c.taggedByObjectIds).join(","),
                            asArray(c.matchedActions).join(","),
                            asArray(c.scopedObjects).map((obj) => `${obj.id}|${obj.displayName}`).join(","),
                        ].join("|");
                        if (!row.classificationEntries.has(classificationKey)) {
                            row.classificationEntries.set(classificationKey, { ...c, reviewAssignments: new Map() });
                        }
                        row.classificationEntries.get(classificationKey).reviewAssignments.set(
                            `${o.roleSystem}|${assignmentKey(ra)}|${ra.roleAssignmentScopeId || scopeName}`,
                            {
                                roleSystem: o.roleSystem,
                                roleAssignmentInstanceId: assignmentKey(ra),
                                roleAssignmentScopeId: ra.roleAssignmentScopeId,
                                roleAssignmentScopeName: scopeName,
                            }
                        );
                        row.principals.set(o.objectId, o.objectDisplayName || o.objectId);
                    });
                });
            })
        );
        const unique = Array.from(map.values());
        unique.forEach((r) => {
            r._sortSys = (r.roleSystem || "").toLowerCase();
            r._sortScope = String(r.roleAssignmentScopeName).toLowerCase();
            r._sortRole = (r.roleDefinitionName || "").toLowerCase();
            r._sortService = String(r.service).toLowerCase();
        });
        unique.sort(
            (a, b) =>
                cmpStr(a._sortSys, b._sortSys) ||
                cmpStr(a.adminTierLevel, b.adminTierLevel) ||
                cmpStr(a._sortScope, b._sortScope) ||
                cmpStr(a._sortRole, b._sortRole) ||
                cmpStr(a._sortService, b._sortService)
        );
        renderCache.classifications = unique;
        return renderCache.classifications;
    }

    function renderClassificationTable() {
        const allRows = buildClassifications();
        currentClassifications = allRows;
        document.getElementById("classificationCount").textContent = allRows.length + " classification(s)";
        document.getElementById("cnt-classification").textContent = allRows.length.toLocaleString();
        const rows = allRows.slice(0, state.limits.classification);
        renderPager("classificationPager", "classification", allRows.length, renderClassificationTable);

        const tbody = document.querySelector("#classificationTable tbody");
        tbody.innerHTML = rows
            .map((r, i) => {
                const sysIco = SYSTEM_ICON[r.roleSystem] || ["&#10067;", r.roleSystem];
                return (
                    `<tr>` +
                    `<td><span class="ico-cell" title="${escAttr(sysIco[1])}"><span class="ico-glyph">${sysIco[0]}</span><span class="cell-truncate">${esc(sysIco[1])}</span></span></td>` +
                    `<td title="${escAttr(r.roleAssignmentScopeName || "—")}"><span class="cell-truncate">${esc(r.roleAssignmentScopeName || "—")}</span></td>` +
                    `<td class="cell-strong" title="${escAttr(r.roleDefinitionName || "—")}"><span class="cell-truncate">${esc(r.roleDefinitionName || "—")}</span></td>` +
                    `<td>${tierBadge(r.adminTierLevel)}</td>` +
                    `<td title="${escAttr(r.service || "—")}"><span class="cell-truncate">${esc(r.service || "—")}</span></td>` +
                    `<td title="${escAttr(r.taggedBy || "—")}"><span class="cell-truncate">${esc(r.taggedBy || "—")}</span></td>` +
                    `<td title="${escAttr(r.taggedByObjectDisplayName || "N/A")}"><span class="cell-truncate">${esc(r.taggedByObjectDisplayName || "N/A")}</span></td>` +
                    `<td title="${escAttr(r.taggedByRoleSystem || "—")}"><span class="cell-truncate">${esc(r.taggedByRoleSystem || "—")}</span></td>` +
                    `<td class="col-icon"><button type="button" class="detail-btn${r.scopeReasoning.size ? " detail-btn-scope" : ""}" data-reasoning="${i}" title="Show classification reasoning and scope details" aria-label="Show classification reasoning and scope details for ${escAttr(r.roleDefinitionName || "role classification")}">&#9432;</button></td>` +
                    `<td class="col-icon"><button type="button" class="detail-btn" data-det="${i}" title="Show all classification details">&#187;</button></td>` +
                    `</tr>`
                );
            })
            .join("") || `<tr><td colspan="10"><div class="empty">No role classifications match the current filters.</div></td></tr>`;
        tbody.querySelectorAll("[data-reasoning]").forEach((btn) =>
            btn.addEventListener("click", () => openClassificationDetails(rows[Number(btn.dataset.reasoning)], true))
        );
        // Full-context detail blade.
        tbody.querySelectorAll("[data-det]").forEach((btn) =>
            btn.addEventListener("click", () => openClassificationDetails(rows[Number(btn.dataset.det)]))
        );
    }

    // ---- Drawer (context blade) ----------------------------------------------------
    const drawer = document.getElementById("drawer");
    const backdrop = document.getElementById("drawerBackdrop");

    let drawerReturnFocus = null; // element focused before the dialog opened

    function openDrawer(title, bodyHtml) {
        document.getElementById("drawerTitle").textContent = title;
        document.getElementById("drawerBody").innerHTML = bodyHtml;
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

    // Delegated drawer handlers. The drawer body is rebuilt on every open, so listeners are attached once
    // to the container rather than to the generated nodes (and CSP forbids inline handlers).
    const drawerBodyEl = document.getElementById("drawerBody");

    drawerBodyEl.addEventListener("click", (e) => {
        const star = e.target.closest("[data-review-action]");
        if (star) {
            e.stopPropagation();
            const on = EOReview.toggle(JSON.parse(star.dataset.reviewAction));
            EOReview.updateStar(star, on);
            return;
        }
        const jump = e.target.closest("[data-jump-evidence]");
        if (!jump) return;
        e.preventDefault();
        const target = document.getElementById(jump.getAttribute("data-jump-evidence"));
        if (!target) return;
        // The section lives inside the collapsed "Show complete classification evidence" block.
        const details = target.closest("details.decision-evidence");
        if (details) details.open = true;
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        target.classList.add("scope-flash");
        setTimeout(() => target.classList.remove("scope-flash"), 1400);
    });

    drawerBodyEl.addEventListener("change", (e) => {
        const toggle = e.target.closest("[data-scope-filter]");
        if (!toggle) return;
        const target = document.getElementById(toggle.getAttribute("data-scope-filter"));
        if (target) target.classList.toggle("scope-reasoning-filtered", toggle.checked);
    });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeDrawer();
    });

    function kvList(pairs) {
        return (
            `<dl class="kv">` +
            pairs
                .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v === undefined || v === null || v === "" ? "—" : v)}</dd>`)
                .join("") +
            `</dl>`
        );
    }

    function listPanel(items) {
        return (
            `<ul class="list-reset drawer-list">` +
            items.map((i) => `<li>${esc(i)}</li>`).join("") +
            `</ul>`
        );
    }

    // ---- Full-context detail blades (&#8505; columns) ---------------------------
    function sectionTitle(t) {
        return `<div class="section-title">${esc(t)}</div>`;
    }

    // Like kvList, but values are pre-rendered (already escaped) HTML fragments.
    function kvHtml(pairs) {
        return (
            `<dl class="kv">` +
            pairs
                .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v || '<span class="muted">&mdash;</span>'}</dd>`)
                .join("") +
            `</dl>`
        );
    }

    function dash(v) {
        return v === undefined || v === null || v === "" ? "" : esc(v);
    }

    function mono(v) {
        return v ? `<span class="cell-mono" style="word-break:break-all;">${esc(v)}</span>` : "";
    }

    // Scope reasoning arrives in generator order. Sort most-privileged-first so the entry that actually
    // drives the effective tier is the first one read, consistent with sortedClassificationEntries().
    function sortedScopeReasoning(scopeReasoning) {
        return asArray(scopeReasoning).slice().sort(
            (a, b) =>
                TIER_ORDER.indexOf(a.eamTier || "Unclassified") - TIER_ORDER.indexOf(b.eamTier || "Unclassified") ||
                cmpStr(String(a.resourceName || a.resourceId || "").toLowerCase(), String(b.resourceName || b.resourceId || "").toLowerCase())
        );
    }

    // Control Plane only toggle. Rendered as a checkbox that flips a class on the container, so filtering
    // needs no re-render and no inline handler (the page CSP forbids inline script).
    function scopeReasoningFilterHtml(entries, filterId) {
        if (!filterId || entries.length < 2) return "";
        const controlPlaneCount = entries.filter((s) => (s.eamTier || "") === "ControlPlane").length;
        if (!controlPlaneCount || controlPlaneCount === entries.length) return "";
        return (
            `<div class="scope-filter-bar">` +
            `<label class="chip scope-filter-toggle"><input type="checkbox" data-scope-filter="${escAttr(filterId)}"/> Control Plane only</label>` +
            `<span class="muted">${esc(controlPlaneCount.toLocaleString())} of ${esc(entries.length.toLocaleString())} scope reason(s) are Control Plane</span>` +
            `</div>`
        );
    }

    function scopeReasoningHtml(scopeReasoning, filterId) {
        if (!scopeReasoning || !scopeReasoning.length) return "";
        const ordered = sortedScopeReasoning(scopeReasoning);
        const items = ordered
            .map((s) => {
                let criticalityRules = asArray(s.criticalityRules).filter(Boolean);
                if (criticalityRules.length === 1 && typeof criticalityRules[0] === "string") {
                    try {
                        const parsed = JSON.parse(criticalityRules[0]);
                        if (Array.isArray(parsed)) criticalityRules = parsed.filter(Boolean);
                    } catch (_) { /* The source may provide a plain rule name instead of JSON. */ }
                }
                const isCriticalAsset = s.source === "ExposureManagement" && s.criticalityLevel !== undefined && s.criticalityLevel !== null;
                const link = s.managedIdentityObjectId
                    ? `<a class="cell-link" href="#asset=${encodeURIComponent(s.managedIdentityObjectId)}" target="_blank" rel="noopener">View privileged asset &#8599;</a>`
                    : "";
                const resultingScope = s.resultingScope ? ` <span class="chip">${esc(s.resultingScope)} scope</span>` : "";
                const tierEvidence = asArray(s.tierEvidence).filter(Boolean);
                const tierEvidenceHtml = tierEvidence.length
                    ? `<ul class="scope-reasoning-list">${tierEvidence.map((evidence) => `<li>${esc(evidence)}</li>`).join("")}</ul>`
                    : "";
                const expandedScopePaths = asArray(s.expandedScopePaths).filter(Boolean);
                const expandedScopePathsHtml = expandedScopePaths.length
                    ? `<ul class="scope-reasoning-list">${expandedScopePaths.map((path) => `<li>${mono(path)}</li>`).join("")}</ul>`
                    : "";
                const affectedObjects = asArray(s.affectedObjects).filter((object) => object && (object.id || object.displayName));
                const affectedObjectsHtml = affectedObjects.length
                    ? `<ul class="scope-reasoning-list">${affectedObjects.map((object) => `<li>${esc(object.displayName || object.id)}${object.id ? `<br/>${mono(object.id)}` : ""}</li>`).join("")}</ul>`
                    : "";
                const classifiedResources = asArray(s.classifiedResources).filter(Boolean);
                const classifiedResourcesHtml = classifiedResources.length
                    ? `<ul class="scope-reasoning-list">${classifiedResources.map((resource) =>
                        `<li>${tierBadge(resource.eamTier || "Unclassified")} <span class="cell-strong">${esc(resource.resourceName || resource.resourceId || "")}</span>` +
                        `${resource.originSystem ? ` <span class="chip">${esc(resource.originSystem)}</span>` : ""}` +
                        `${resource.resourceId ? `<br/>${mono(resource.resourceId)}` : ""}` +
                        `${resource.reason ? `<br/><span class="muted">${esc(resource.reason)}</span>` : ""}</li>`
                    ).join("")}</ul>`
                    : "";
                return (
                    `<li class="scope-reasoning-entry${isCriticalAsset ? " is-critical-asset" : ""}" data-tier="${escAttr(s.eamTier || "Unclassified")}">` +
                    `<div>${tierBadge(s.eamTier || "Unclassified")}${resultingScope} <span class="cell-strong">${esc(s.resourceName || s.resourceId || "")}</span></div>` +
                    kvHtml([
                        ["Resource Id", mono(s.resourceId)],
                        ["Source", dash(s.source)],
                        ["Assignment scope relation", dash(s.scopeRelation)],
                        ["Criticality level", isCriticalAsset ? esc(s.criticalityLevel) : ""],
                        ["Criticality rules", criticalityRules.length ? `<ul class="scope-reasoning-list">${criticalityRules.map((rule) => `<li>${esc(rule)}</li>`).join("")}</ul>` : ""],
                        ["Classification reason", dash(s.reason)],
                        ["Tier source", dash(s.tierSource)],
                        ["Tier evidence", tierEvidenceHtml],
                        ["Scope category", dash(s.scopeCategory)],
                        ["Scope type", dash(s.scopeType)],
                        ["Catalog", dash(s.catalogDisplayName)],
                        ["Expanded scope paths", expandedScopePathsHtml],
                        ["Affected scoped objects", affectedObjectsHtml],
                        ["Classified assigned resources", classifiedResourcesHtml],
                        ["Privileged asset", link],
                    ]) +
                    `</li>`
                );
            })
            .join("");
        return scopeReasoningFilterHtml(ordered, filterId) + `<ul class="list-reset drawer-list">${items}</ul>`;
    }

    function controlPlaneReasoningHtml(reasoningEntries) {
        const entries = asArray(reasoningEntries);
        if (!entries.length) return "";
        const items = [];
        entries.forEach((entry) => {
            const sources = asArray(entry.classificationSources).filter(Boolean).join(", ") || "Unknown source";
            const reasons = asArray(entry.classificationReasons).filter(Boolean);
            if (!reasons.length) {
                items.push(`<li><span class="cell-strong">${esc(sources)}</span><br/><span class="muted">Control Plane classification evidence was recorded without a detailed reason.</span></li>`);
            }
            reasons.forEach((reason) => {
                let text = reason.value || "";
                if (reason.roleSystem) text = `Control Plane assignment found in ${reason.roleSystem}`;
                if (reason.roleName) text = `${reason.roleName}${reason.roleScope ? ` at ${reason.roleScope}` : ""}`;
                if (reason.edgeLabel) text = `${reason.edgeLabel}${reason.targetNodeName ? ` → ${reason.targetNodeName}` : ""}`;
                if (text === "ObjectAdminTierLevelName") text = "Object-level tier is Control Plane";
                if (text) items.push(`<li><span class="cell-strong">${esc(sources)}</span><br/><span class="muted">${esc(text)}</span></li>`);
            });
        });
        return items.length ? `<ul class="list-reset drawer-list">${items.join("")}</ul>` : "";
    }

    function assignmentClassificationMode(r, classEntries) {
        const tags = new Set(classEntries.map((entry) => entry.taggedBy).filter(Boolean));
        const scopeReasons = asArray(r.scopeReasoning);
        if (r.conditionEvaluation || r.roleAssignmentCondition || asArray(r.roleDefinitionConditions).length || tags.has("JSONwithConditionInScope")) return "Conditional delegation";
        if (tags.has("RoleDefinitionOverwrites") || tags.has("RoleActionOverwrites")) return "Manual overwrite";
        if (tags.has("CloudSetAzureScopeReasoning")) return "Azure CloudSet inheritance";
        if (scopeReasons.some((reason) => asArray(reason.classifiedResources).length)) return "Assigned-resource inheritance";
        if (scopeReasons.some((reason) => asArray(reason.expandedScopePaths).length || asArray(reason.affectedObjects).length)) return "Dynamic scope";
        if (Array.from(tags).some((tag) => tag.startsWith("Fallback")) || classEntries.some((entry) => entry.adminTierLevelName === "Unclassified")) return "Conservative fallback";
        return "Static permission";
    }

    // Condense the scope reasoning into one readable line: which tier it produced, how the assignment scope
    // relates to the classified resource(s), and which resource actually drove it - plus a jump link into
    // the full "Scope impact and propagation" section, so the reader does not have to expand and scan the
    // complete evidence block to find out why the scope mattered.
    function scopeRelationshipStep(scopeReasons, evidenceScopeId) {
        const ordered = sortedScopeReasoning(scopeReasons);
        const driver = ordered[0];
        const driverTier = (driver && driver.eamTier) || "Unclassified";

        const relationCounts = new Map();
        ordered.forEach((s) => {
            const key = s.scopeRelation || "Related";
            relationCounts.set(key, (relationCounts.get(key) || 0) + 1);
        });
        const relationText = Array.from(relationCounts.entries())
            .sort((a, b) => b[1] - a[1] || cmpStr(a[0], b[0]))
            .map(([relation, count]) => `${count.toLocaleString()} ${relation.toLowerCase()}`)
            .join(", ");

        const driverName = driver ? (driver.resourceName || driver.resourceId || "") : "";
        const driverSource = driver && driver.source ? ` via ${driver.source}` : "";
        const otherCount = ordered.length - 1;

        let valueHtml =
            `${tierBadge(driverTier)} ` +
            `<span>${esc(ordered.length.toLocaleString())} scope reason(s): ${esc(relationText)}</span>`;
        if (driverName) {
            valueHtml +=
                `<br/><span>Driven by <span class="cell-strong">${esc(driverName)}</span>${esc(driverSource)}` +
                `${otherCount > 0 ? ` and ${esc(otherCount.toLocaleString())} further scope reason(s)` : ""}.</span>`;
        }
        if (driver && driver.reason) valueHtml += `<br/><span>${esc(driver.reason)}</span>`;
        if (evidenceScopeId) {
            valueHtml +=
                `<br/><button type="button" class="cell-link scope-jump" data-jump-evidence="${escAttr(evidenceScopeId)}">` +
                `Jump to scope impact and propagation &#8595;</button>`;
        }
        return { label: "Scope relationship", value: `${ordered.length.toLocaleString()} exact or descendant scope reason(s)`, valueHtml };
    }

    function assignmentDecision(r, classEntries, evidenceScopeId) {
        const sorted = sortedClassificationEntries(classEntries);
        const effective = sorted[0] || { adminTierLevelName: "Unclassified", service: "" };
        const effectiveEntries = sorted.filter((entry) => entry.adminTierLevelName === effective.adminTierLevelName);
        const actions = Array.from(new Set(effectiveEntries.flatMap((entry) => asArray(entry.matchedActions))));
        const services = Array.from(new Set(effectiveEntries.map((entry) => entry.service).filter(Boolean)));
        const scopeReasons = asArray(r.scopeReasoning);
        const classifiedResources = scopeReasons.flatMap((reason) => asArray(reason.classifiedResources));
        const affectedObjects = scopeReasons.flatMap((reason) => asArray(reason.affectedObjects));
        const propagatedPaths = scopeReasons.flatMap((reason) => asArray(reason.expandedScopePaths));
        const cloudSetSubscriptions = scopeReasons
            .filter((reason) => reason.source === "Defender CloudSet")
            .flatMap((reason) => asArray(reason.subscriptionScopes));
        const mode = assignmentClassificationMode(r, sorted);
        const effectiveTierLabel = TIER_TEXT[effective.adminTierLevelName] || effective.adminTierLevelName;

        let cause = actions.length
            ? `${actions.length.toLocaleString()} matched ${actions.length === 1 ? "capability is" : "capabilities are"} classified as ${effectiveTierLabel}`
            : `the persisted classification is ${effectiveTierLabel}`;
        if (classifiedResources.length) {
            const winning = classifiedResources.filter((resource) => resource.eamTier === effective.adminTierLevelName);
            cause += ` and ${winning.length || classifiedResources.length} assigned resource${(winning.length || classifiedResources.length) === 1 ? " determines" : "s determine"} the scope tier`;
        } else if (affectedObjects.length) {
            cause += ` and ${affectedObjects.length} affected scoped object${affectedObjects.length === 1 ? " requires" : "s require"} this scope`;
        } else if (propagatedPaths.length) {
            cause += " and the assignment scope reaches a classified descendant resource";
        } else if (cloudSetSubscriptions.length) {
            cause += ` and ${cloudSetSubscriptions.length} CloudSet subscription${cloudSetSubscriptions.length === 1 ? " determines" : "s determine"} the scope tier`;
        }
        if (r.conditionEvaluation && r.conditionEvaluation.summary) cause += `. ${r.conditionEvaluation.summary}`;

        const steps = [];
        steps.push({ label: "Role capability", value: actions.length ? `${actions.length.toLocaleString()} matched action(s) across ${services.join(", ") || "the classification rules"}` : "Persisted role or object classification" });
        steps.push({ label: "Classification rule", value: `${mode}${services.length ? ` for ${services.join(", ")}` : ""}` });
        if (r.conditionEvaluation) steps.push({ label: "Condition evaluation", value: r.conditionEvaluation.summary || r.conditionEvaluation.status });
        if (classifiedResources.length) steps.push({ label: "Assigned resources", value: `${classifiedResources.length.toLocaleString()} resource(s) were evaluated; the most privileged result determines the scope tier` });
        else if (affectedObjects.length) steps.push({ label: "Scope driver", value: `${affectedObjects.length.toLocaleString()} affected scoped object(s)` });
        else if (scopeReasons.length) steps.push(scopeRelationshipStep(scopeReasons, evidenceScopeId));
        else steps.push({ label: "Scope relationship", value: "The classification rule applies directly at the assignment scope" });
        steps.push({ label: "Result", value: `${effectiveTierLabel} at ${r.roleAssignmentScopeName || r.roleAssignmentScopeId || "the assigned scope"}` });

        return { effective, mode, summary: `${r.roleDefinitionName || "This assignment"} is ${effectiveTierLabel} because ${cause}.`, steps };
    }

    function decisionChainHtml(steps) {
        // step.valueHtml is pre-escaped markup built by the step producer; step.value stays the plain-text
        // fallback and is escaped here.
        return `<div class="attack-chain">${steps.map((step, index) =>
            `<div class="attack-step"><span class="step-n">${index + 1}</span><div class="step-body"><span class="cell-strong">${esc(step.label)}</span><br/><span class="muted">${step.valueHtml || esc(step.value)}</span></div></div>`
        ).join("")}</div>`;
    }

    function conditionEvidenceHtml(r) {
        const roleConditions = asArray(r.roleDefinitionConditions);
        const evaluation = r.conditionEvaluation;
        const constraints = evaluation ? asArray(evaluation.constraints) : [];
        if (!r.roleAssignmentCondition && !roleConditions.length && !evaluation) return '<div class="muted">No assignment or role-definition condition applies.</div>';
        return kvHtml([
            ["Evaluation status", evaluation ? dash(evaluation.status) : ""],
            ["Evaluation result", evaluation ? dash(evaluation.summary) : ""],
            ["Assignment condition", r.roleAssignmentCondition ? mono(r.roleAssignmentCondition) : ""],
            ["Assignment condition version", dash(r.roleAssignmentConditionVersion)],
            ["Role-definition conditions", roleConditions.map((condition) => `${mono(condition.condition)}${condition.conditionVersion ? `<br/><span class="muted">Version ${esc(condition.conditionVersion)}</span>` : ""}`).join("<br>")],
            ["Parsed delegation constraints", constraints.map((constraint) => `${esc(constraint.source || "Condition")} ${esc(constraint.operator || "")}:<br/>${asArray(constraint.roleDefinitionIds).map(mono).join("<br>")}`).join("<br>")],
        ]);
    }

    function principalControlPlaneReasoningHtml(entries) {
        const records = asArray(entries);
        if (!records.length) return '<div class="muted">No persisted object-level Control Plane reasoning is attached to the assigned principals.</div>';
        return records.map((record) =>
            `<div class="scope-reasoning-entry"><span class="cell-strong">${esc(record.displayName || record.objectId || "Assigned principal")}</span>${record.objectId ? `<br/>${mono(record.objectId)}` : ""}` +
            controlPlaneReasoningHtml([record.reasoning || record]) + `</div>`
        ).join("");
    }

    function assignmentDecisionHtml(r, classEntries, evidenceScopeId) {
        const decision = assignmentDecision(r, classEntries, evidenceScopeId);
        return (
            sectionTitle("Classification verdict") +
            `<div class="callout control"><div class="decision-meta">${tierBadge(decision.effective.adminTierLevelName)} <span class="chip">${esc(decision.mode)}</span></div><div>${esc(decision.summary)}</div></div>` +
            sectionTitle("Decision chain") + decisionChainHtml(decision.steps)
        );
    }

    // Scopes listed per action in the evidence of a classification row (starred scopes are always listed).
    const REVIEW_ACTION_SCOPE_LIMIT = 5;

    function reviewActionList(actions, assignments, tier) {
        const reviewIds = window.EOReview ? EOReview.idsSet() : new Set();
        return '<ul class="list-reset drawer-list">' + actions.map((action) => {
            if (!window.EOReview) {
                return `<li><span class="cell-mono" style="word-break:break-all;">${esc(action)}</span></li>`;
            }
            const contexts = new Map();
            assignments.forEach((assignment) => {
                const scope = assignment.roleAssignmentScopeId || assignment.roleAssignmentScopeName || "";
                const id = EOReview.makeId("action", assignment.roleSystem, action, scope);
                if (!contexts.has(id)) contexts.set(id, {
                    id, kind: "Role action", system: assignment.roleSystem, name: action, scope, tier,
                    hash: "#assignment=" + encodeURIComponent(assignment.roleAssignmentInstanceId) +
                        "&action=" + encodeURIComponent(action),
                });
            });
            if (!contexts.size) {
                return `<li><span class="cell-mono" style="word-break:break-all;">${esc(action)}</span></li>`;
            }
            // A classification row can cover many assignment scopes: starred scopes first, then up to the
            // limit, so a role with many actions and scopes doesn't render thousands of rows.
            const items = Array.from(contexts.values());
            const shown = items.filter((item) => reviewIds.has(item.id))
                .concat(items.filter((item) => !reviewIds.has(item.id)))
                .slice(0, Math.max(REVIEW_ACTION_SCOPE_LIMIT, items.filter((item) => reviewIds.has(item.id)).length));
            const more = items.length - shown.length;
            return shown.map((item) => {
                const star = EOReview.starHtml(item.id, undefined, reviewIds.has(item.id)).replace("<button ",
                    `<button data-eo-id="${escAttr(item.id)}" data-review-action="${escAttr(JSON.stringify(item))}" `);
                return `<li>${star} <span class="cell-mono" style="word-break:break-all;">${esc(action)}</span>` +
                    `<div class="muted cell-mono" style="word-break:break-all;">${esc(item.system)} &middot; ${esc(item.scope || "Scope not available")}</div></li>`;
            }).join("") + (more > 0
                ? `<li class="muted" data-review-action-more>${esc(more.toLocaleString())} more scope(s) of this action: star it in the classification reasoning of its role assignment.</li>`
                : "");
        }).join("") + "</ul>";
    }

    function principalList(principals) {
        // principals: Map(objectId -> displayName), rendered sorted by name.
        const entries = Array.from(principals.entries()).sort((a, b) =>
            cmpStr(String(a[1]).toLowerCase(), String(b[1]).toLowerCase())
        );
        if (!entries.length) return '<div class="muted">&mdash;</div>';
        return (
            `<ul class="list-reset drawer-list">` +
            entries
                .map(([id, nm]) => `<li>${esc(nm)} <span class="cell-mono muted" style="word-break:break-all;">(${esc(id)})</span></li>`)
                .join("") +
            `</ul>`
        );
    }

    function sortedClassificationEntries(entries) {
        return Array.from(entries).sort(
            (a, b) =>
                TIER_ORDER.indexOf(a.adminTierLevelName || "Unclassified") - TIER_ORDER.indexOf(b.adminTierLevelName || "Unclassified") ||
                cmpStr(String(a.service || "").toLowerCase(), String(b.service || "").toLowerCase())
        );
    }

    function classificationEvidenceHtml(entries, assignment) {
        const classifications = sortedClassificationEntries(entries);
        if (!classifications.length) {
            return '<div class="muted">No persisted classification evidence is available.</div>';
        }
        return classifications
            .map((classification, index) => {
                const actions = Array.from(new Set(asArray(classification.matchedActions))).sort();
                const taggedObjects = asArray(classification.taggedByObjectDisplayNames);
                const scopedObjects = asArray(classification.scopedObjects);
                return (
                    sectionTitle(`Applied classification ${index + 1} of ${classifications.length}`) +
                    kvHtml([
                        ["Access level", tierBadge(classification.adminTierLevelName || "Unclassified")],
                        ["Service", dash(classification.service)],
                        ["Classification method", dash(classification.taggedBy)],
                        ["Classification system", dash(classification.taggedByRoleSystem)],
                        ["Tagged by objects", taggedObjects.map(esc).join("<br>")],
                        ["Scoped objects", scopedObjects.map((obj) => `${esc(obj.displayName || obj.id)} <span class="cell-mono muted">(${esc(obj.id || "")})</span>`).join("<br>")],
                        ["Role actions leading to this access level", actions.length ? esc(actions.length.toLocaleString() + " action(s)") : ""],
                    ]) +
                    (actions.length ? reviewActionList(actions,
                        assignment ? [assignment] : Array.from(classification.reviewAssignments.values()),
                        classification.adminTierLevelName || "Unclassified")
                        : '<div class="muted">No matched role actions were persisted for this classification entry.</div>')
                );
            })
            .join("");
    }

    // Monotonic id source so several assignment evidence blocks can coexist in one drawer
    // (openAssetClassification renders one per contributing assignment) without colliding ids.
    let evidenceSeq = 0;
    function nextEvidenceScopeId() {
        evidenceSeq += 1;
        return `eo-evidence-scope-${evidenceSeq}`;
    }

    function assignmentCompleteEvidenceHtml(r, classEntries, controlPlaneEntries = [], evidenceScopeId) {
        const sysIco = SYSTEM_ICON[r.roleSystem] || ["&#10067;", r.roleSystem];
        let html =
            sectionTitle("Role and assignment") +
            kvHtml([
                ["RBAC system", `<span class="ico-glyph">${sysIco[0]}</span> ${esc(sysIco[1])}`],
                ["Role", `<span class="cell-strong">${esc(r.roleDefinitionName || "")}</span>`],
                ["Role definition Id", mono(r.roleDefinitionId)],
                ["Role assignment Id", mono(r.roleAssignmentId)],
                ["Assignment type", dash(r.roleAssignmentType)],
                ["Scope", dash(r.roleAssignmentScopeName)],
                ["Scope Id", mono(r.roleAssignmentScopeId)],
                ["Product/application scopes", asArray(r.applicationScopes).map(esc).join("<br>")],
            ]) +
            sectionTitle("Condition evidence") + conditionEvidenceHtml(r) +
            sectionTitle("Applied classification rules") + classificationEvidenceHtml(classEntries, r) +
            sectionTitle("Object-level Control Plane reasoning") + principalControlPlaneReasoningHtml(controlPlaneEntries);
        const scopeAnchor = evidenceScopeId ? ` id="${escAttr(evidenceScopeId)}"` : "";
        if (asArray(r.scopeReasoning).length) {
            html += `<div class="scope-impact-section"${scopeAnchor}>` +
                sectionTitle("Scope impact and propagation") + scopeReasoningHtml(r.scopeReasoning, evidenceScopeId) +
                `</div>`;
        } else {
            html += `<div class="scope-impact-section"${scopeAnchor}>` +
                sectionTitle("Scope impact and propagation") +
                '<div class="muted">No dynamic scope propagation was required; the classification rule applies directly at this assignment scope.</div>' +
                `</div>`;
        }
        return `<details class="decision-evidence"><summary>Show complete classification evidence</summary><div class="decision-evidence-body">${html}</div></details>`;
    }

    function openAssignmentClassification(r) {
        const sysIco = SYSTEM_ICON[r.roleSystem] || ["&#10067;", r.roleSystem];
        const classEntries = Array.from(r.classEntries.values());
        const evidenceScopeId = nextEvidenceScopeId();
        const html =
            assignmentDecisionHtml(r, classEntries, evidenceScopeId) +
            assignmentCompleteEvidenceHtml(r, classEntries, [], evidenceScopeId);
        openDrawer("Classification reasoning — " + (r.roleDefinitionName || r.roleAssignmentId), html);
    }

    function openAssetClassification(r) {
        const objectClassifications = sortedClassificationEntries(r.objClassification.values());
        const assignments = Array.from(r.assignmentEvidence.values()).sort(
            (a, b) => cmpStr(String(a.roleDefinitionName || "").toLowerCase(), String(b.roleDefinitionName || "").toLowerCase())
        );
        let html =
            sectionTitle("Effective object classification") +
            kvHtml([
                ["Object tier", tierBadge(r.objectAdminTierLevelName)],
                ["Applied access levels", objectClassifications.length
                    ? objectClassifications.map((classification) => `${tierBadge(classification.adminTierLevelName)} ${esc(classification.service || "")}`).join("<br>")
                    : ""],
                ["Contributing assignments", esc(assignments.length.toLocaleString())],
            ]);
        const persistedReasoning = controlPlaneReasoningHtml(Array.from(r.controlPlaneReasoning.values()));
        if (persistedReasoning) {
            html += sectionTitle("Persisted object-tier reasoning") + persistedReasoning;
        }
        if (!assignments.length) {
            html += sectionTitle("Assignment evidence") + '<div class="muted">No contributing role assignments are available.</div>';
        }
        assignments.forEach((assignment, index) => {
            const classEntries = Array.from(assignment.classification.values());
            const principalReasoning = Array.from(r.controlPlaneReasoning.values()).map((reasoning) => ({
                objectId: r.objectId,
                displayName: r.objectDisplayName || r.objectId,
                reasoning,
            }));
            const evidenceScopeId = nextEvidenceScopeId();
            html +=
                sectionTitle(`Contributing assignment ${index + 1} of ${assignments.length}`) +
                assignmentDecisionHtml(assignment, classEntries, evidenceScopeId) +
                assignmentCompleteEvidenceHtml(assignment, classEntries, principalReasoning, evidenceScopeId);
        });
        openDrawer("Classification reasoning — " + (r.objectDisplayName || r.objectId), html);
    }

    function openAssetDetails(r) {
        const typeIco = TYPE_ICON[r.objectType] || TYPE_ICON.unknown;
        const rmIco = RM_ICON[r.restrictedManagement] || RM_ICON["Not available"];
        const classEntries = Array.from(r.objClassification.values()).sort(
            (a, b) =>
                TIER_ORDER.indexOf(a.adminTierLevelName || "Unclassified") - TIER_ORDER.indexOf(b.adminTierLevelName || "Unclassified") ||
                cmpStr(String(a.service || "").toLowerCase(), String(b.service || "").toLowerCase())
        );
        const linked = r.linkedIdentity.map((id) => {
            const nm = displayNameForId(id);
            return nm ? `${esc(nm)} <span class="cell-mono muted">(${esc(id)})</span>` : mono(id);
        });
        const controlPlaneReasoning = controlPlaneReasoningHtml(Array.from(r.controlPlaneReasoning.values()));
        const html =
            sectionTitle("Principal") +
            kvHtml([
                ["Type", `<span class="ico-glyph">${typeIco[0]}</span> ${esc(typeIco[1])}`],
                ["Sub type", dash(r.objectSubType)],
                ["Display name", `<span class="cell-strong" style="word-break:break-word;">${esc(r.objectDisplayName || "")}</span>`],
                ["User principal name", dash(r.objectUserPrincipalName)],
                ["Object Id", mono(r.objectId)],
                ["Object tenant Id", mono(r.objectTenantId)],
                ["Privileged type", dash(r.privilegedType)],
                ["Outside of home tenant", esc(yesNo(r.outsideOfHomeTenant))],
                ["Sync source", dash(r.syncSource)],
                ["Origin", dash(r.originType)],
                ["Origin tenant Id", r.originTenantId ? mono(r.originTenantId) : dash("")],
                ["Origin Id", r.originId ? mono(r.originId) : dash("")],
            ]) +
            sectionTitle("Classification") +
            kvHtml([
                ["Object tier", tierBadge(r.objectAdminTierLevelName)],
                [
                    "Access classification",
                    classEntries.length
                        ? classEntries.map((c) => `${tierBadge(c.adminTierLevelName)} ${esc(c.service || "")}`).join("<br>")
                        : "",
                ],
            ]) +
            (controlPlaneReasoning
                ? sectionTitle("Why this object is Control Plane") + controlPlaneReasoning
                : "") +
            sectionTitle("Restricted management") +
            kvHtml([
                ["Status", `${rmIco[0]} ${esc(rmIco[1])}`],
                ["By Entra ID role", esc(yesNo(r.restricted.RestrictedManagementByAadRole))],
                ["By Role-assignable Group", esc(yesNo(r.restricted.RestrictedManagementByRAG))],
                ["By RMAU", esc(yesNo(r.restricted.RestrictedManagementByRMAU))],
            ]) +
            sectionTitle("Directory context") +
            kvHtml([
                [
                    "RBAC systems",
                    Array.from(r.roleSystems)
                        .sort()
                        .map((s) => {
                            const ico = SYSTEM_ICON[s] || ["&#10067;", s];
                            return `<span class="ico-glyph">${ico[0]}</span> ${esc(ico[1])}`;
                        })
                        .join("<br>"),
                ],
                ["Role assignments", esc(r.assignmentCount.toLocaleString())],
                [
                    "Administrative units",
                    r.adminUnits.length
                        ? r.adminUnits.map((au) => `${esc(au.displayName || au.id)} <span class="cell-mono muted">(${esc(au.id)})</span>`).join("<br>")
                        : "",
                ],
                ["Linked identities", linked.join("<br>")],
            ]);
        openDrawer("Asset details — " + (r.objectDisplayName || r.objectId), html);
    }

    function openAssignmentDetails(r) {
        const sysIco = SYSTEM_ICON[r.roleSystem] || ["&#10067;", r.roleSystem];
        const html =
            sectionTitle("Role definition") +
            kvHtml([
                ["RBAC system", `<span class="ico-glyph">${sysIco[0]}</span> ${esc(sysIco[1])}`],
                ["Role", `<span class="cell-strong">${esc(r.roleDefinitionName || "")}</span>`],
                ["Role definition Id", mono(r.roleDefinitionId)],
                ["Role type", dash(r.roleType)],
                ["Privileged role", esc(yesNo(r.roleIsPrivileged))],
            ]) +
            sectionTitle("Assignment") +
            kvHtml([
                ["Role assignment Id", mono(r.roleAssignmentId)],
                ["Assignment type", dash(r.roleAssignmentType)],
                ["Assignment subtype", dash(r.transitiveByAssignment)],
                ["PIM managed role", esc(yesNo(r.pimManagedRole))],
                ["PIM assignment type", dash(r.pimAssignmentType)],
                ["Eligibility by", dash(r.eligibilityBy)],
            ]) +
            sectionTitle("Scope") +
            kvHtml([
                ["Scope name", dash(r.roleAssignmentScopeName)],
                ["Scope Id", mono(r.roleAssignmentScopeId)],
                ["Product/application scopes", asArray(r.applicationScopes).map(esc).join("<br>")],
            ]) +
            sectionTitle("Conditions") + conditionEvidenceHtml(r) +
            sectionTitle("Transitivity") +
            kvHtml([
                ["Transitive by", dash(r.transitiveBy)],
                ["Transitive by object Id", mono(r.transitiveByObjectId)],
                ["Nested via", r.transitiveByNesting.length ? r.transitiveByNesting.map(esc).join("<br>") : ""],
            ]) +
            sectionTitle("Assigned principals (" + r.principals.size + ")") +
            principalList(r.principals);
        openDrawer("Role assignment — " + (r.roleDefinitionName || r.roleAssignmentId), html);
    }

    function openClassificationDetails(r, focusReasoning = false) {
        const sysIco = SYSTEM_ICON[r.roleSystem] || ["&#10067;", r.roleSystem];
        const scopePropagation = Array.from(r.scopeReasoning.values());
        const html =
            (focusReasoning ? sectionTitle("Classification reasoning") : "") +
            sectionTitle("Role definition") +
            kvHtml([
                ["RBAC system", `<span class="ico-glyph">${sysIco[0]}</span> ${esc(sysIco[1])}`],
                ["Role", `<span class="cell-strong">${esc(r.roleDefinitionName || "")}</span>`],
                ["Role definition Id(s)", Array.from(r.roleDefinitionIds).sort().map(mono).join("<br>")],
                ["Role type(s)", Array.from(r.roleTypes).sort().map(esc).join("<br>")],
                ["Tier level", tierBadge(r.adminTierLevel)],
                ["Service", dash(r.service)],
            ]) +
            sectionTitle("Role assignment") +
            kvHtml([
                ["Role assignment Id(s)", Array.from(r.roleAssignmentIds).sort().map(mono).join("<br>")],
                ["Assignment type(s)", Array.from(r.assignmentTypes).sort().map(esc).join("<br>")],
                ["PIM assignment type(s)", Array.from(r.pimAssignmentTypes).sort().map(esc).join("<br>")],
                ["Eligibility by", Array.from(r.eligibilityBy).sort().map(esc).join("<br>")],
                ["Assignment condition(s)", Array.from(r.assignmentConditions).sort().map(esc).join("<br>")],
                ["Condition version(s)", Array.from(r.assignmentConditionVersions).sort().map(esc).join("<br>")],
            ]) +
            sectionTitle("Scope") +
            kvHtml([
                ["Scope name", dash(r.roleAssignmentScopeName)],
                ["Scope Id(s)", Array.from(r.scopeIds).sort().map(mono).join("<br>")],
                ["Product/application scopes", Array.from(r.applicationScopes).sort().map(esc).join("<br>")],
            ]) +
            (scopePropagation.length
                ? sectionTitle("Resource scope propagation") + scopeReasoningHtml(scopePropagation)
                : sectionTitle("Resource scope propagation") + '<div class="muted">No persisted resource-scope propagation evidence is available for this classification.</div>') +
            sectionTitle("Classification evidence") +
            classificationEvidenceHtml(r.classificationEntries.values()) +
            sectionTitle("Tagged by") +
            kvHtml([
                ["Tagged by", dash(r.taggedBy)],
                ["Tagged by object", dash(r.taggedByObjectDisplayName)],
                ["Tagged by object Id(s)", Array.from(r.taggedByObjectIds).sort().map(mono).join("<br>")],
                ["Tagged by system", dash(r.taggedByRoleSystem)],
            ]) +
            sectionTitle("Scoped objects (" + r.scopedObjects.size + ")") +
            principalList(r.scopedObjects) +
            sectionTitle("Held by principals (" + r.principals.size + ")") +
            principalList(r.principals);
        openDrawer("Role classification — " + (r.roleDefinitionName || ""), html);
    }

    // ---- CSV export -------------------------------------------------------------
    function exportCsv(filename, cols, rows) {
        const csvCell = (v) => {
            const s = v === null || v === undefined ? "" : Array.isArray(v) ? v.join("; ") : v instanceof Set ? Array.from(v).join("; ") : String(v);
            // Neutralise spreadsheet formula injection before RFC-4180 quoting. Excel and Sheets execute a
            // cell whose text begins with = + - @ (or a leading tab/CR), and these exports carry tenant
            // display names, which are attacker-influenceable (a guest can set their own). A leading
            // apostrophe forces the cell to be treated as literal text.
            var csvSafe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
            return /[",\n\r]/.test(csvSafe) ? '"' + csvSafe.replace(/"/g, '""') + '"' : csvSafe;
        };
        const lines = [cols.map((c) => c[1]).join(",")];
        rows.forEach((r) => lines.push(cols.map((c) => csvCell(r[c[0]])).join(",")));
        const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    document.getElementById("assetCsv").addEventListener("click", () =>
        exportCsv("entraops-privileged-assets.csv", [
            ["objectType", "ObjectType"],
            ["objectSubType", "ObjectSubType"],
            ["objectDisplayName", "ObjectDisplayName"],
            ["objectAdminTierLevelName", "ObjectAdminTierLevelName"],
            ["restrictedManagement", "RestrictedManagement"],
            ["syncSource", "SyncSource"],
            ["roleSystems", "RoleSystems"],
            ["objectId", "ObjectId"],
            ["objectTenantId", "ObjectTenantId"],
        ], currentAssets)
    );
    document.getElementById("assignmentCsv").addEventListener("click", () =>
        exportCsv("entraops-role-assignments.csv", [
            ["roleSystem", "RoleSystem"],
            ["adminTierLevel", "AdminTierLevel"],
            ["roleDefinitionName", "RoleDefinitionName"],
            ["roleType", "RoleType"],
            ["roleAssignmentScopeName", "RoleAssignmentScopeName"],
            ["roleAssignmentScopeId", "RoleAssignmentScopeId"],
            ["pimAssignmentType", "PIMAssignmentType"],
            ["roleAssignmentType", "RoleAssignmentType"],
            ["eligibilityBy", "EligibilityBy"],
            ["transitiveBy", "TransitiveBy"],
            ["transitiveByAssignment", "TransitiveByAssignment"],
            ["transitiveByNesting", "TransitiveByNestingObjectDisplayNames"],
            ["services", "Service"],
            ["roleAssignmentId", "RoleAssignmentId"],
        ], currentAssignments)
    );
    document.getElementById("classificationCsv").addEventListener("click", () =>
        exportCsv("entraops-role-classification.csv", [
            ["roleSystem", "RoleSystem"],
            ["roleAssignmentScopeName", "RoleAssignmentScopeName"],
            ["roleDefinitionName", "RoleDefinitionName"],
            ["adminTierLevel", "AdminTierLevel"],
            ["service", "Service"],
            ["taggedBy", "TaggedBy"],
            ["taggedByObjectDisplayName", "TaggedByObjectDisplayName"],
            ["taggedByRoleSystem", "TaggedByRoleSystem"],
        ], currentClassifications)
    );

    // ---- Navigation --------------------------------------------------------------
    document.getElementById("navToggle").addEventListener("click", () => {
        document.getElementById("nav").classList.toggle("open");
    });
    document.querySelectorAll(".nav-item.section-item").forEach((el) =>
        el.addEventListener("click", () => {
            scrollToSection(el.dataset.target);
            document.getElementById("nav").classList.remove("open");
        })
    );

    function scrollToSection(sectionId) {
        document.getElementById(sectionId).scrollIntoView({ behavior: "auto", block: "start" });
    }

    // ---- Helpers -------------------------------------------------------------------
    function asArray(v) {
        if (v === null || v === undefined || v === "") return [];
        return Array.isArray(v) ? v : [v];
    }

    function dedupeById(records) {
        const seen = new Set();
        return records.filter((o) => {
            if (seen.has(o.objectId)) return false;
            seen.add(o.objectId);
            return true;
        });
    }

    function tierBadge(tierName) {
        const t = tierName && TIER_TEXT[tierName] ? tierName : "Unclassified";
        // No leading dot: the badge's own background/border color already conveys
        // the tier, and the dot only added width without extra information.
        return `<span class="tier-badge ${TIER_BADGE_CLASS[t]}"><span class="tier-label">${esc(TIER_TEXT[t])}</span></span>`;
    }

    function yesNo(v) {
        return v ? "Yes" : "No";
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

    function escAttr(s) {
        return esc(s);
    }

    // ---- Main render -----------------------------------------------------------------
    function render() {
        renderCache = Object.create(null);
        renderExportChips();
        renderSyncTiles();
        renderRestrictedPie();
        renderAssignmentPie();
        renderObjectTierTiles();
        renderAccessTierTiles();
        renderAssetTable();
        renderAssignmentTable();
        renderClassificationTable();
    }

    // ---- Cross-app deep link (Privilege History "Open in EAM Dashboard Overview") ---------
    // Privilege History is a separate static-web app (Reports/PrivilegeHistory) and doesn't share a
    // JS context with this page, so it hands off its filters via URL query parameters instead:
    //   ?rs=<comma-list|*>          RBAC System multi-select
    //   &tier=<comma-list|*>        RBAC Tier Level (classification AdminTierLevelName)
    //   &objectTier=<name[,name]|*> Identity classification (ObjectAdminTierLevelName), one or several tiers
    //   &q=<text>                   Search (display name, role name, scope name, role actions)
    //   #secOverview                (anchor scroll handled natively by the browser)
    // Values that don't exist as filter options are silently dropped, so a stale or
    // foreign link can never produce a filter selection the UI has no checkbox or
    // tile to clear again.
    function applyQueryDeepLink() {
        const params = new URLSearchParams(location.search);
        if (!params.has("rs") && !params.has("tier") && !params.has("objectTier") && !params.has("q")) return;
        const rs = params.get("rs");
        const tier = params.get("tier");
        const objectTier = params.get("objectTier");
        if (rs !== null) {
            state.roleSystems = rs === "*" || rs === "" ? null : new Set(rs.split(","));
            const host = document.getElementById("fltRoleSystem");
            if (host._refreshOptions) host._refreshOptions(allSystems);
        }
        if (tier !== null) {
            // Keep only tiers that exist as RBAC Tier Level checkbox options.
            const known = tier === "*" || tier === "" ? [] : tier.split(",").filter((t) => allTiers.includes(t));
            state.tierLevels = known.length ? new Set(known) : null;
            const host = document.getElementById("fltTierLevel");
            if (host._refreshOptions) host._refreshOptions(allTiers);
        }
        if (objectTier !== null && objectTier !== "*" && objectTier !== "") {
            // Identity-classification filter - the same mechanism as clicking a "Classification of privileged
            // identities" tile, clearable via its export chip; several tiers (Privilege History hand-over) are kept.
            const known = objectTier.split(",").filter((t) => TIER_ORDER.includes(t));
            if (known.length) state.objectTier = known.join(",");
        }
        // &q=<text>: the search (display name, role name, scope name, role actions), e.g. the role search of the
        // Privilege History.
        const query = params.get("q");
        if (query) {
            state.displayName = query.trim().toLowerCase();
            const searchInput = document.getElementById("fltDisplayName");
            if (searchInput) searchInput.value = query.trim();
        }
        const svcHost = document.getElementById("fltService");
        if (svcHost && svcHost._refreshOptions) svcHost._refreshOptions(serviceOptions());
        resetPagination();
        render();
    }

    window.addEventListener("hashchange", applyDeepLink);
    render();
    applyDeepLink();
    applyQueryDeepLink();
})();
