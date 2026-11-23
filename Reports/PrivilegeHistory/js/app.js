/*
 * EntraOps Privilege History
 *
 * Historic trends built from the git history of the Privileged EAM export
 * (New-EntraOpsPrivilegedEamPrivilegeHistoryData). Part of Privileged EAM Reporting;
 * "Open in EAM Dashboard Overview" navigates to the EAM Dashboard app with the
 * current RBAC System / Tier Level filters carried over via URL query
 * parameters (?rs=...&tier=...) - the two apps don't share a JS context since
 * each is its own static-web page.
 *
 * Data contract: window.ENTRAOPS_PRIVILEGEHISTORY_DATA = {
 *   generatedAt, tierOrder, rbacSystems, timeRangeInDays,
 *   snapshots: [{ commitSha, commitDate, rbacSystems, totals, objectTier, accessTier, hasDetail, objects }]
 * }
 * Optional: window.ENTRAOPS_EAM_DATA (loaded from ../EamDashboard/data/eam-dashboard-data.js
 * when present) is used to show "then vs. now" deltas against today's live data.
 */
(function () {
    "use strict";

    const DATA_TM = window.ENTRAOPS_PRIVILEGEHISTORY_DATA;
    const emptyState = document.getElementById("tmEmptyState");
    const content = document.getElementById("tmContent");
    if (DATA_TM && typeof DATA_TM.tenantName === "string" && DATA_TM.tenantName.trim()) {
        document.getElementById("tenantName").textContent = DATA_TM.tenantName.trim();
    }

    // ---- Navigation (shared shell behavior across every reporting app) ---------------
    document.getElementById("navToggle").addEventListener("click", () => {
        document.getElementById("nav").classList.toggle("open");
    });
    document.querySelectorAll(".nav-item.section-item").forEach((el) => {
        const activate = () => {
            const target = document.getElementById(el.dataset.target);
            if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
            document.getElementById("nav").classList.remove("open");
        };
        el.addEventListener("click", activate);
        el.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" && e.key !== " ") return;
            e.preventDefault();
            activate();
        });
    });

    if (!DATA_TM || !Array.isArray(DATA_TM.snapshots) || DATA_TM.snapshots.length === 0) {
        emptyState.classList.remove("hidden");
        content.classList.add("hidden");
        return;
    }

    emptyState.classList.add("hidden");
    content.classList.remove("hidden");

    // Without git history the page shows the current export only: the trends need snapshots from git.
    if (DATA_TM.historySource === "folder") {
        const folderNote = document.getElementById("tmFolderNote");
        if (folderNote) {
            folderNote.hidden = false;
            folderNote.textContent = "This report shows the current Privileged EAM export only: it was generated without git history " +
                "(-HistorySource Folder, or Auto outside a git repository). Commit the exports to a repository and generate the report with " +
                "-HistorySource Git or Auto to see trends and to compare points in time.";
        }
    }

    const TIER_ORDER = Array.isArray(DATA_TM.tierOrder) && DATA_TM.tierOrder.length
        ? DATA_TM.tierOrder
        : ["ControlPlane", "ManagementPlane", "WorkloadPlane", "UserAccess", "Unclassified"];
    const TIER_COLOR = {
        ControlPlane: "#a4262c",
        ManagementPlane: "#c07807",
        WorkloadPlane: "#0078d4",
        UserAccess: "#0e700e",
        Unclassified: "#8a8886",
    };
    const TIER_TEXT = {
        ControlPlane: "Control Plane",
        ManagementPlane: "Management Plane",
        WorkloadPlane: "Workload Plane",
        UserAccess: "User Access",
        Unclassified: "Unclassified",
    };
    function tierLabel(t) { return TIER_TEXT[t] || t; }
    function tierColor(t) { return TIER_COLOR[t] || "#8a8886"; }
    function tierRank(t) {
        const i = TIER_ORDER.indexOf(t);
        return i < 0 ? TIER_ORDER.length - 1 : i;
    }

    const snapshots = DATA_TM.snapshots
        .slice()
        .sort((a, b) => new Date(a.commitDate) - new Date(b.commitDate));
    const allRbacSystems = Array.isArray(DATA_TM.rbacSystems) && DATA_TM.rbacSystems.length
        ? DATA_TM.rbacSystems
        : uniqueSorted(snapshots.flatMap((s) => s.rbacSystems || []));

    function uniqueSorted(arr) {
        return Array.from(new Set(arr.filter((v) => v))).sort((a, b) => String(a).localeCompare(String(b)));
    }

    function esc(s) {
        return String(s).replace(/[&<>"']/g, (c) => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
        }[c]));
    }

    function fmtDate(iso) {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    }

    function fmtDateShort(iso) {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
    }

    // Without git (-HistorySource Folder, or Auto outside a repository) the current export is the only snapshot.
    const FOLDER_MODE = DATA_TM.historySource === "folder";

    // Short commit id; uncommitted exports and exports without git history have no commit.
    function snapshotLabel(s) {
        if (s.workingTree) return FOLDER_MODE ? "current export" : "working tree";
        const sha = String(s.commitSha || "");
        return sha.startsWith("(") ? sha.replace(/^\(|\)$/g, "") : sha.substring(0, 7);
    }

    // ---- State -----------------------------------------------------------------------
    const state = {
        roleSystems: [], // multi-select facets of pills: [] = all, else the selected values
        tierLevels: [],
        roleSearch: "",
        fromIdx: 0,
        toIdx: snapshots.length - 1,
        selectedIdx: null,
    };

    // ---- Filters (RBAC System / Tier Level / Role search) - apply to the snapshot
    //      detail & compare tables; the trend charts always show totals across every
    //      RBAC system and tier since that's what was aggregated at generation time. ----
    EntraOpsFilters.bindPills(document.getElementById("tmFacets"), state, () => renderSnapshotDetail());
    document.getElementById("tmFltRole").addEventListener("input", debounce((e) => {
        state.roleSearch = e.target.value.trim().toLowerCase();
        renderSnapshotDetail();
    }, 180));

    function debounce(fn, wait) {
        let t;
        return function (...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), wait);
        };
    }

    // The snapshot the pills count: the selected one, else the latest one of the time range with
    // object-level detail.
    function facetSnapshotIdx() {
        if (state.selectedIdx !== null) return state.selectedIdx;
        for (let i = state.toIdx; i >= state.fromIdx; i--) {
            if (Array.isArray(snapshots[i].objects) && snapshots[i].objects.length) return i;
        }
        return state.toIdx;
    }

    // Pills of the RBAC systems and tier levels, with the number of privileged objects of the counted
    // snapshot that match the other filters. A snapshot lists an object once per RBAC system it holds
    // roles in, so the pills count distinct object IDs.
    function renderFacets() {
        const idx = facetSnapshotIdx();
        const objects = snapshots[idx].objects || [];
        const objectKey = (o) => o.objectId;
        const systems = EntraOpsFilters.facetCounts(objects, "roleSystems", objectMatches, (o) => o.roleSystem, objectKey);
        const tiers = EntraOpsFilters.facetCounts(objects, "tierLevels", objectMatches, (o) => o.objectAdminTierLevelName || "Unclassified", objectKey);
        const multi = { multi: true };
        document.getElementById("tmFltRoleSystem").innerHTML = EntraOpsFilters.pill(state, "roleSystems", "", "All", systems.total, multi) +
            allRbacSystems.map((system) => EntraOpsFilters.pill(state, "roleSystems", system, system, systems.counts[system] || 0, multi)).join("");
        document.getElementById("tmFltTierLevel").innerHTML = EntraOpsFilters.pill(state, "tierLevels", "", "All", tiers.total, multi) +
            TIER_ORDER.map((tier) => EntraOpsFilters.tierPill(state, "tierLevels", tier, tierLabel(tier), tiers.counts[tier] || 0, multi)).join("");
        document.getElementById("tmFacetScope").textContent = `Number of privileged objects in the ${state.selectedIdx === null ? "latest " : ""}snapshot of ` +
            `${fmtDate(snapshots[idx].commitDate)} (${snapshotLabel(snapshots[idx])})` +
            (snapshots[idx].hasDetail === false ? " - trend only, without object-level detail" : "") +
            ", each counted once across RBAC systems. Groups are included; the asset charts count users and service principals only.";
    }

    // ---- Time range selects ------------------------------------------------------------
    const rangeFrom = document.getElementById("tmRangeFrom");
    const rangeTo = document.getElementById("tmRangeTo");
    const compareBaseline = document.getElementById("tmCompareBaseline");
    const compareCurrent = document.getElementById("tmCompareCurrent");

    function snapshotOptionsHtml(includeLive) {
        return snapshots.map((s, i) => `<option value="${i}">${esc(fmtDate(s.commitDate))} (${esc(snapshotLabel(s))})${s.hasDetail === false ? " - trend only" : ""}</option>`).join("") +
            (includeLive ? `<option value="live">Live (now)</option>` : "");
    }

    rangeFrom.innerHTML = snapshotOptionsHtml(false);
    rangeTo.innerHTML = snapshotOptionsHtml(false);
    rangeFrom.value = String(state.fromIdx);
    rangeTo.value = String(state.toIdx);
    compareBaseline.innerHTML = snapshotOptionsHtml(false);
    compareCurrent.innerHTML = snapshotOptionsHtml(window.ENTRAOPS_EAM_DATA ? true : false);
    compareBaseline.value = "0";
    compareCurrent.value = window.ENTRAOPS_EAM_DATA ? "live" : String(state.toIdx);

    rangeFrom.addEventListener("change", () => {
        state.fromIdx = Math.min(Number(rangeFrom.value), state.toIdx);
        rangeFrom.value = String(state.fromIdx);
        renderCharts();
        renderFacets();
    });
    rangeTo.addEventListener("change", () => {
        state.toIdx = Math.max(Number(rangeTo.value), state.fromIdx);
        rangeTo.value = String(state.toIdx);
        renderCharts();
        renderFacets();
    });
    document.getElementById("tmResetRange").addEventListener("click", () => {
        state.fromIdx = 0;
        state.toIdx = snapshots.length - 1;
        rangeFrom.value = "0";
        rangeTo.value = String(state.toIdx);
        renderCharts();
        renderFacets();
    });

    // ---- Charts ------------------------------------------------------------------------
    function seriesInRange() {
        return snapshots.slice(state.fromIdx, state.toIdx + 1).map((s, i) => ({ snapshot: s, idx: state.fromIdx + i }));
    }

    function renderCharts() {
        renderTierTrendChart("tmChartAssets", (s) => s.objectTier, "assets");
        renderTierTrendChart("tmChartUsers", (s) => s.objectTier, "users");
        renderTierTrendChart("tmChartAssignments", (s) => s.accessTier, "roleAssignments");
        renderSingleTrendChart("tmChartBreaches", (s) => s.totals.tierBreaches, "#a4262c", "Tier breaches");
    }

    function renderTierTrendChart(hostId, tierSeriesOf, valueKey) {
        const pts = seriesInRange();
        const host = document.getElementById(hostId);
        if (pts.length === 0) {
            host.innerHTML = `<div class="empty">No snapshots in the selected time range.</div>`;
            return;
        }
        const series = TIER_ORDER.map((tier) => ({
            key: tier,
            color: tierColor(tier),
            label: tierLabel(tier),
            points: pts.map((p) => {
                const row = (tierSeriesOf(p.snapshot) || []).find((r) => r.tier === tier);
                return { idx: p.idx, date: p.snapshot.commitDate, value: row ? Number(row[valueKey]) || 0 : 0 };
            }),
        })).filter((s) => s.points.some((p) => p.value > 0));
        drawLineChart(host, series, pts.length);
    }

    function renderSingleTrendChart(hostId, valueOf, color, label) {
        const pts = seriesInRange();
        const host = document.getElementById(hostId);
        if (pts.length === 0) {
            host.innerHTML = `<div class="empty">No snapshots in the selected time range.</div>`;
            return;
        }
        const series = [{
            key: "breaches", color, label,
            points: pts.map((p) => ({ idx: p.idx, date: p.snapshot.commitDate, value: Number(valueOf(p.snapshot)) || 0 })),
        }];
        drawLineChart(host, series, pts.length);
    }

    function drawLineChart(host, series, pointCount) {
        // All-zero snapshots leave no series after the value>0 filter - render the
        // empty state instead of dereferencing series[0] below.
        if (series.length === 0) {
            host.innerHTML = `<div class="empty">No data in the selected time range.</div>`;
            return;
        }
        const width = 560, height = 220, padL = 40, padR = 12, padT = 12, padB = 28;
        const plotW = width - padL - padR, plotH = height - padT - padB;
        const allValues = series.flatMap((s) => s.points.map((p) => p.value));
        const maxV = Math.max(1, ...allValues);
        const first = series[0].points;
        const t0 = new Date(first[0].date).getTime();
        const t1 = new Date(first[first.length - 1].date).getTime();
        const span = Math.max(1, t1 - t0);

        function xAt(date) {
            if (pointCount === 1) return padL + plotW / 2;
            return padL + ((new Date(date).getTime() - t0) / span) * plotW;
        }
        function yAt(v) { return padT + plotH - (v / maxV) * plotH; }

        const gridLines = 4;
        let grid = "";
        for (let i = 0; i <= gridLines; i++) {
            const y = padT + (plotH / gridLines) * i;
            const val = Math.round(maxV - (maxV / gridLines) * i);
            grid += `<line x1="${padL}" y1="${y}" x2="${width - padR}" y2="${y}" stroke="#edebe9" stroke-width="1"/>` +
                `<text x="${padL - 6}" y="${y + 4}" text-anchor="end" font-size="10" fill="#605e5c">${val.toLocaleString()}</text>`;
        }

        let paths = "";
        let dots = "";
        series.forEach((s) => {
            const d = s.points.map((p, i) => `${i === 0 ? "M" : "L"} ${xAt(p.date).toFixed(1)} ${yAt(p.value).toFixed(1)}`).join(" ");
            paths += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2"/>`;
            s.points.forEach((p) => {
                const selected = state.selectedIdx === p.idx;
                dots += `<circle cx="${xAt(p.date).toFixed(1)}" cy="${yAt(p.value).toFixed(1)}" r="${selected ? 5 : 3}" ` +
                    `fill="${s.color}" stroke="${selected ? "#201f1e" : "#fff"}" stroke-width="${selected ? 2 : 1}" ` +
                    `class="tm-point" data-idx="${p.idx}"><title>${esc(tierLabel(s.key) || s.label)}: ${p.value.toLocaleString()} (${esc(fmtDate(p.date))})</title></circle>`;
            });
        });

        const legend = series.map((s) =>
            `<div class="li"><span class="sw" style="background:${s.color}"></span><span class="nm">${esc(s.label)}</span></div>`
        ).join("");

        host.innerHTML =
            `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">` +
            grid +
            `<text x="${padL}" y="${height - 6}" font-size="10" fill="#605e5c">${esc(fmtDateShort(first[0].date))}</text>` +
            `<text x="${width - padR}" y="${height - 6}" text-anchor="end" font-size="10" fill="#605e5c">${esc(fmtDateShort(first[first.length - 1].date))}</text>` +
            paths + dots +
            `</svg><div class="donut-legend tm-legend">${legend}</div>`;

        host.querySelectorAll(".tm-point").forEach((c) =>
            c.addEventListener("click", () => selectSnapshot(Number(c.dataset.idx)))
        );
    }

    // ---- Live totals (from the optional EAM Dashboard dataset) ------------------------
    // Memoized: the EAM dataset never changes at runtime, and a full aggregate() on every
    // renderSnapshotDetail (each filter keystroke) is needlessly expensive at large scale.
    let liveTotalsCache;
    function getLiveTotals() {
        if (liveTotalsCache !== undefined) return liveTotalsCache;
        const liveData = window.ENTRAOPS_EAM_DATA;
        if (!liveData || !Array.isArray(liveData.objects)) {
            liveTotalsCache = null;
            return liveTotalsCache;
        }
        const agg = aggregate(liveData.objects);
        liveTotalsCache = { assets: agg.totals.assets, users: agg.totals.users, roleAssignments: agg.totals.roleAssignments };
        return liveTotalsCache;
    }

    // ---- Snapshot detail ---------------------------------------------------------------
    function selectSnapshot(idx) {
        state.selectedIdx = idx;
        renderCharts();
        renderSnapshotDetail();
    }

    // skip leaves out one facet, for the counts of its pills.
    function objectMatches(o, skip) {
        if (skip !== "roleSystems" && !EntraOpsFilters.matchesFacet(state, "roleSystems", o.roleSystem)) return false;
        if (skip !== "tierLevels" && !EntraOpsFilters.matchesFacet(state, "tierLevels", o.objectAdminTierLevelName || "Unclassified")) return false;
        if (state.roleSearch) {
            const hit = (o.roleAssignments || []).some((ra) => (ra.roleDefinitionName || "").toLowerCase().includes(state.roleSearch));
            if (!hit) return false;
        }
        return true;
    }

    function filteredSnapshotObjects(snapshot) {
        return (snapshot.objects || []).filter((o) => objectMatches(o));
    }

    function renderSnapshotDetail() {
        const chip = document.getElementById("tmSnapshotChip");
        const jumpBtn = document.getElementById("tmJumpToOverview");
        const body = document.getElementById("tmSnapshotBody");
        renderFacets();

        if (state.selectedIdx === null) {
            chip.classList.add("hidden");
            jumpBtn.classList.add("hidden");
            body.innerHTML = `<div class="muted">Click a point on any chart above to inspect a historic snapshot.</div>`;
            return;
        }

        const snapshot = snapshots[state.selectedIdx];
        const objs = filteredSnapshotObjects(snapshot);
        const live = getLiveTotals();

        chip.classList.remove("hidden");
        chip.textContent = `${fmtDate(snapshot.commitDate)} \u00b7 ${snapshotLabel(snapshot)}`;
        jumpBtn.classList.remove("hidden");
        jumpBtn.onclick = () => {
            const rs = state.roleSystems.length ? state.roleSystems.join(",") : "*";
            // This app's tier filter matches objectAdminTierLevelName (identity
            // classification), so it maps to EamDashboard's objectTier parameter -
            // not its `tier` parameter, which filters classification tiers.
            const objectTier = state.tierLevels.length ? state.tierLevels.join(",") : "*";
            const params = new URLSearchParams({ rs, objectTier });
            // The role search is handed over as the EAM Dashboard search (it also matches role names).
            if (state.roleSearch) params.set("q", state.roleSearch);
            location.href = `../EamDashboard/index.html?${params.toString()}#secOverview`;
        };

        const detailNote = snapshot.hasDetail === false
            ? `<p class="hint">Object-level detail was not kept for this snapshot to bound the dataset size
                (see <code>-MaxDetailedSnapshots</code>) - showing trend totals only.</p>`
            : "";

        const deltaBadge = (histVal, liveVal) => {
            if (live === null) return "";
            const d = liveVal - histVal;
            if (d === 0) return `<span class="tm-delta tm-flat">no change</span>`;
            return `<span class="tm-delta ${d > 0 ? "tm-up" : "tm-down"}">${d > 0 ? "+" : ""}${d.toLocaleString()} vs. today</span>`;
        };

        const assetRows = objs.slice(0, 200).map((o) =>
            `<tr><td>${esc(o.objectType)}</td><td>${esc(o.objectDisplayName)}</td>` +
            `<td>${tierBadge(o.objectAdminTierLevelName)}</td><td>${esc(o.roleSystem)}</td>` +
            `<td>${(o.roleAssignments || []).length}</td></tr>`
        ).join("");
        const assetNote = objs.length > 200
            ? `<p class="hint">Showing first 200 of ${objs.length.toLocaleString()} rows (one per object and RBAC system).</p>`
            : "";

        const assignmentList = objs.flatMap((o) => (o.roleAssignments || []).map((ra) => ({ o, ra })))
            .filter(({ ra }) => !state.roleSearch || (ra.roleDefinitionName || "").toLowerCase().includes(state.roleSearch));
        const assignmentRows = assignmentList
            .slice(0, 200)
            .map(({ o, ra }) =>
                `<tr><td>${esc(o.objectDisplayName)}</td><td>${esc(ra.roleSystem)}</td><td>${esc(ra.roleDefinitionName)}</td>` +
                `<td>${esc(ra.roleAssignmentType)} ${esc(ra.pimAssignmentType)}</td>` +
                `<td>${(ra.classification || []).map((c) => tierBadge(c.adminTierLevelName)).join(" ")}</td></tr>`
            ).join("");
        const assignmentNote = assignmentList.length > 200
            ? `<p class="hint">Showing first 200 of ${assignmentList.length.toLocaleString()} role assignments.</p>`
            : "";

        // hasDetail === false snapshots carry no object-level rows at all - say so instead of
        // implying the current filters excluded everything.
        const assetEmptyText = snapshot.hasDetail === false
            ? "Detailed asset data was not captured for this snapshot (trend-only)."
            : "No privileged assets match the current filters.";
        const assignmentEmptyText = snapshot.hasDetail === false
            ? "Detailed asset data was not captured for this snapshot (trend-only)."
            : "No role assignments match the current filters.";

        const liveHint = live === null
            ? `<p class="hint">Load <code>../EamDashboard/data/eam-dashboard-data.js</code> (generate it with
                <code>New-EntraOpsPrivilegedEamDashboardData</code>) to see deltas vs. today's live data.</p>`
            : "";

        body.innerHTML =
            detailNote + liveHint +
            `<div class="eam-tiles" style="margin-bottom:16px;">` +
            `<div class="eam-tile"><div class="t-label">Privileged assets</div><div class="t-value">${snapshot.totals.assets.toLocaleString()}</div>${deltaBadge(snapshot.totals.assets, live ? live.assets : 0)}</div>` +
            `<div class="eam-tile"><div class="t-label">Users assigned</div><div class="t-value">${snapshot.totals.users.toLocaleString()}</div>${deltaBadge(snapshot.totals.users, live ? live.users : 0)}</div>` +
            `<div class="eam-tile"><div class="t-label">Role assignments</div><div class="t-value">${snapshot.totals.roleAssignments.toLocaleString()}</div>${deltaBadge(snapshot.totals.roleAssignments, live ? live.roleAssignments : 0)}</div>` +
            `<div class="eam-tile"><div class="t-label">Tier breaches</div><div class="t-value">${snapshot.totals.tierBreaches.toLocaleString()}</div></div>` +
            `</div>` +
            `<div class="table-wrap eam-scroll">` +
            `<table class="grid-table"><thead><tr><th>Type</th><th>Display name</th><th>Object tier</th><th>RBAC system</th><th>Assignments</th></tr></thead>` +
            `<tbody>${assetRows || `<tr><td colspan="5" class="empty">${esc(assetEmptyText)}</td></tr>`}</tbody></table>` +
            `</div>` +
            assetNote +
            `<div class="table-wrap eam-scroll" style="margin-top:10px;">` +
            `<table class="grid-table"><thead><tr><th>Principal</th><th>System</th><th>Role</th><th>Assignment</th><th>Tier</th></tr></thead>` +
            `<tbody>${assignmentRows || `<tr><td colspan="5" class="empty">${esc(assignmentEmptyText)}</td></tr>`}</tbody></table>` +
            `</div>` +
            assignmentNote;
    }

    function tierBadge(tierName) {
        const t = tierName && TIER_TEXT[tierName] ? tierName : "Unclassified";
        return `<span class="tier-badge" style="background:${tierColor(t)}22;color:${tierColor(t)};border:1px solid ${tierColor(t)}55;border-radius:10px;padding:1px 8px;font-size:11.5px;white-space:nowrap;">${esc(tierLabel(t))}</span>`;
    }

    // ---- Compare two points in time -----------------------------------------------------
    // The tierBreaches computed here intentionally matches the generator's definition
    // (New-EntraOpsPrivilegedEamPrivilegeHistoryData: unique classification tiers per role
    // assignment, counted when tierRank(tier) < tierRank(object tier), an unclassified object
    // compared as User Access), so client-side aggregates and snapshot.totals.tierBreaches agree.
    // Assets and role assignments are counted like the generator too: assets without groups, and an assignment
    // once per roleAssignmentInstanceId (else roleAssignmentId), so the latest snapshot shows no delta vs. today.
    function aggregate(objects) {
        const assetMap = new Map();
        const assetsByTier = {}, usersByTier = {}, assignByTier = {};
        TIER_ORDER.forEach((t) => { assetsByTier[t] = 0; usersByTier[t] = 0; assignByTier[t] = 0; });
        const seenAssignment = new Set();
        let totalAssignments = 0, totalUsers = 0, tierBreaches = 0, totalAssets = 0;

        objects.forEach((o) => {
            const tier = o.objectAdminTierLevelName || "Unclassified";
            if (!assetMap.has(o.objectId)) {
                assetMap.set(o.objectId, { tier, type: o.objectType, name: o.objectDisplayName });
                if (o.objectType !== "group") { assetsByTier[tier] = (assetsByTier[tier] || 0) + 1; totalAssets++; }
                if (o.objectType === "user") { usersByTier[tier] = (usersByTier[tier] || 0) + 1; totalUsers++; }
            }
            // An unclassified object is compared as User Access: only a role above User Access is a breach.
            const objRank = tierRank(tier === "Unclassified" ? "UserAccess" : tier);
            (o.roleAssignments || []).forEach((ra) => {
                const assignmentKey = ra.roleAssignmentInstanceId || ra.roleAssignmentId;
                if (!assignmentKey || !seenAssignment.has(assignmentKey)) {
                    if (assignmentKey) seenAssignment.add(assignmentKey);
                    totalAssignments++;
                }
                const tiers = (ra.classification || []).map((c) => c.adminTierLevelName).filter(Boolean);
                const raTiers = tiers.length ? Array.from(new Set(tiers)) : ["Unclassified"];
                raTiers.forEach((t) => {
                    assignByTier[t] = (assignByTier[t] || 0) + 1;
                    if (tierRank(t) < objRank) tierBreaches++;
                });
            });
        });

        return {
            assetMap, assetsByTier, usersByTier, assignByTier,
            totals: { assets: totalAssets, users: totalUsers, roleAssignments: totalAssignments, tierBreaches },
        };
    }

    function objectsForCompareValue(val) {
        if (val === "live") return (window.ENTRAOPS_EAM_DATA && window.ENTRAOPS_EAM_DATA.objects) || [];
        return snapshots[Number(val)].objects || [];
    }

    function labelForCompareValue(val) {
        if (val === "live") return "Live (now)";
        const s = snapshots[Number(val)];
        return `${fmtDate(s.commitDate)} (${snapshotLabel(s)})`;
    }

    document.getElementById("tmCompareRun").addEventListener("click", () => {
        const baseVal = compareBaseline.value;
        const curVal = compareCurrent.value;
        const baseHasDetail = baseVal === "live" || snapshots[Number(baseVal)].hasDetail !== false;
        const curHasDetail = curVal === "live" || snapshots[Number(curVal)].hasDetail !== false;
        if (!baseHasDetail || !curHasDetail) {
            document.getElementById("tmCompareResult").innerHTML =
                `<div class="empty">Object-level detail was not kept for one of the selected snapshots (see -MaxDetailedSnapshots) - pick a snapshot without "trend only" in its label.</div>`;
            return;
        }
        const baseAgg = aggregate(objectsForCompareValue(baseVal));
        const curAgg = aggregate(objectsForCompareValue(curVal));

        const added = [];
        const removed = [];
        const tierChanged = [];
        curAgg.assetMap.forEach((info, id) => {
            if (!baseAgg.assetMap.has(id)) added.push(info);
            else if (baseAgg.assetMap.get(id).tier !== info.tier) {
                tierChanged.push({ name: info.name, from: baseAgg.assetMap.get(id).tier, to: info.tier });
            }
        });
        baseAgg.assetMap.forEach((info, id) => {
            if (!curAgg.assetMap.has(id)) removed.push(info);
        });

        const delta = (a, b) => {
            const d = b - a;
            return `${d > 0 ? "+" : ""}${d.toLocaleString()}`;
        };

        const summaryRows = [
            ["Privileged assets", baseAgg.totals.assets, curAgg.totals.assets],
            ["Users assigned", baseAgg.totals.users, curAgg.totals.users],
            ["Role assignments", baseAgg.totals.roleAssignments, curAgg.totals.roleAssignments],
            ["Tier breaches", baseAgg.totals.tierBreaches, curAgg.totals.tierBreaches],
        ].map(([label, a, b]) => `<tr><td>${esc(label)}</td><td>${a.toLocaleString()}</td><td>${b.toLocaleString()}</td><td>${delta(a, b)}</td></tr>`).join("");

        const listRows = (items) => items.slice(0, 100).map((i) =>
            `<tr><td>${esc(i.type || "")}</td><td>${esc(i.name || "")}</td><td>${tierBadge(i.tier)}</td></tr>`
        ).join("");
        const changedRows = tierChanged.slice(0, 100).map((c) =>
            `<tr><td colspan="2">${esc(c.name)}</td><td>${tierBadge(c.from)} &rarr; ${tierBadge(c.to)}</td></tr>`
        ).join("");

        document.getElementById("tmCompareResult").innerHTML =
            `<p class="hint">Baseline: <strong>${esc(labelForCompareValue(baseVal))}</strong> &middot; Current: <strong>${esc(labelForCompareValue(curVal))}</strong></p>` +
            `<table class="grid-table"><thead><tr><th>Metric</th><th>Baseline</th><th>Current</th><th>Change</th></tr></thead><tbody>${summaryRows}</tbody></table>` +
            `<div class="eam-row" style="margin-top:12px;">` +
            `<section class="card eam-col-50"><div class="card-head">Assets added (${added.length})</div>` +
            `<div class="table-wrap eam-scroll"><table class="grid-table"><thead><tr><th>Type</th><th>Display name</th><th>Tier</th></tr></thead><tbody>${listRows(added) || `<tr><td colspan="3" class="empty">None</td></tr>`}</tbody></table></div></section>` +
            `<section class="card eam-col-50"><div class="card-head">Assets removed (${removed.length})</div>` +
            `<div class="table-wrap eam-scroll"><table class="grid-table"><thead><tr><th>Type</th><th>Display name</th><th>Tier</th></tr></thead><tbody>${listRows(removed) || `<tr><td colspan="3" class="empty">None</td></tr>`}</tbody></table></div></section>` +
            `</div>` +
            `<section class="card" style="margin-top:12px;"><div class="card-head">Tier changed (${tierChanged.length})</div>` +
            `<div class="table-wrap eam-scroll"><table class="grid-table"><thead><tr><th colspan="2">Display name</th><th>Tier change</th></tr></thead><tbody>${changedRows || `<tr><td colspan="3" class="empty">None</td></tr>`}</tbody></table></div></section>`;
    });

    // ---- Initial render ------------------------------------------------------------------
    renderCharts();
    renderSnapshotDetail();
})();
