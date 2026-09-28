/*
 * EntraOps Configuration Analyzer
 *
 * Compares EntraOps Tenant Governance snapshots over time (built from the git history of
 * TenantGovernance/Snapshots by New-EntraOpsTenantGovernanceConfigurationAnalyzerData):
 * change timeline, per-snapshot change list and a two-snapshot comparison, with
 * property-level diffs and a best-effort privileged-asset cross-reference.
 *
 * The Conditional Access policy flow / coverage gaps and EIDSCA coverage views moved to
 * their own apps (Reports/ConditionalAccessAnalysis, Reports/EidscaCoverage), which reuse
 * the snapshot/blob parsing in js/core.js (loaded before this file - see index.html).
 */
(function () {
    "use strict";

    function configurationView() {
        if (/^#resource=/.test(location.hash)) return "resources";
        var requested = new URLSearchParams(location.search).get("view");
        return requested === "resources" || requested === "privileged" ? requested : "configuration";
    }

    function applyConfigurationView() {
        var view = configurationView();
        var visibility = {
            secTimeline: view === "configuration",
            secChanges: view === "configuration",
            secCompare: view === "configuration",
            secAllSnapshotResources: view === "resources",
            secPrivilegedAssets: view === "privileged",
            secRelatedAssets: view === "privileged"
        };
        Object.keys(visibility).forEach(function (id) { $(id).hidden = !visibility[id]; });
        document.querySelectorAll("[data-section-view]").forEach(function (item) {
            item.hidden = item.getAttribute("data-section-view") !== view;
        });
        if ($("caSectionsLabel")) $("caSectionsLabel").hidden = view === "resources";
        ["Configuration", "Resources", "Privileged"].forEach(function (name) {
            var link = $("caNav" + name);
            if (link) link.classList.toggle("active", name.toLowerCase() === view);
        });
        var title = view === "resources" ? "Snapshot Resources" : (view === "privileged" ? "Configuration Assets" : "Configuration Analyzer");
        $("caPageTitle").textContent = title;
        document.title = "EntraOps " + title;
        $("caPageDescription").textContent = view === "resources"
            ? "Browse every resource in a selected Tenant Governance snapshot, inspect structured content, and compare it across snapshots."
            : (view === "privileged"
                ? "Review captured resources that involve classified identities, directly or through resolved group membership."
                : "Compare EntraOps Tenant Governance snapshots over time using the change timeline and property-level comparison.");
    }

    // ---- Diff two snapshots ----------------------------------------------------------
    function diffSnapshots(base, cur, typeFilter) {
        var baseMap = {}, curMap = {};
        base.resources.forEach(function (r) { if (!typeFilter || r.type === typeFilter) baseMap[r.p] = r; });
        cur.resources.forEach(function (r) { if (!typeFilter || r.type === typeFilter) curMap[r.p] = r; });
        var added = [], removed = [], modified = [];
        Object.keys(curMap).forEach(function (p) {
            if (!baseMap[p]) added.push(curMap[p]);
            else if (baseMap[p].h !== curMap[p].h) modified.push({ base: baseMap[p], cur: curMap[p] });
        });
        Object.keys(baseMap).forEach(function (p) {
            if (!curMap[p]) removed.push(baseMap[p]);
        });
        var byName = function (a, b) {
            var an = a.cur ? a.cur.p : a.p, bn = b.cur ? b.cur.p : b.p;
            return an.localeCompare(bn);
        };
        added.sort(byName); removed.sort(byName); modified.sort(byName);
        return { added: added, removed: removed, modified: modified };
    }

    // =====================================================================================
    // Change timeline
    // =====================================================================================
    var TIMELINE_RECENT_COUNT = 12;
    var state = {
        typeFilter: "",
        timelineView: "recent",
        selectedIdx: snapshots.length > 1 ? snapshots.length - 1 : -1,
        // Row-level filters applied inside renderChangeList (after diffSnapshots), shared
        // by both the "Snapshot changes" and "Compare two snapshots" sections.
        categoryFilter: "",
        statusFilter: new Set(["added", "modified", "removed"]),
        privilegedOnly: false,
        tierFilter: "",
        classificationFilter: ""
    };

    function changesAt(idx, typeFilter) {
        if (idx <= 0 || idx >= snapshots.length) return null;
        return diffSnapshots(snapshots[idx - 1], snapshots[idx], typeFilter);
    }

    function renderStats() {
        $("statSnapshots").textContent = snapshots.length.toLocaleString();
        if (snapshots.length > 0) {
            $("statRange").textContent = fmtDateShort(snapshots[0].commitDate) + " → " + fmtDateShort(snapshots[snapshots.length - 1].commitDate);
            var latest = snapshots[snapshots.length - 1];
            $("statResources").textContent = latest.resources.length.toLocaleString();
            $("statResourceTypes").textContent = allResourceTypes().length + " resource types";
            var latestChanges = changesAt(snapshots.length - 1, "");
            $("statLatestChanges").textContent = latestChanges
                ? (latestChanges.added.length + latestChanges.modified.length + latestChanges.removed.length).toLocaleString()
                : "–";
            var caPolicies = latest.resources.filter(function (r) { return isCaPolicyType(r.type); });
            $("statCaPolicies").textContent = caPolicies.length.toLocaleString();
            var parsed = caPoliciesForSnapshot(latest);
            if (parsed.length) {
                var states = { enabled: 0, reportOnly: 0, disabled: 0 };
                parsed.forEach(function (p) { states[p.state] = (states[p.state] || 0) + 1; });
                $("statCaStates").textContent = states.enabled + " enabled · " + states.reportOnly + " report-only · " + states.disabled + " disabled";
            } else {
                $("statCaStates").textContent = caPolicies.length ? "content not embedded for latest snapshot" : "no CA policies captured";
            }
        }
    }

    function renderTypeFilter() {
        var sel = $("fltResourceType");
        var html = '<option value="">All resource types</option>';
        allResourceTypes().forEach(function (t) {
            html += '<option value="' + esc(t) + '"' + (t === state.typeFilter ? " selected" : "") + ">" + esc(t) + "</option>";
        });
        sel.innerHTML = html;
    }

    function timelineEntries() {
        var entries = [];
        for (var i = 1; i < snapshots.length; i++) {
            var diff = changesAt(i, state.typeFilter);
            entries.push({
                idx: i,
                startIdx: i,
                endIdx: i,
                captures: 1,
                label: fmtDateShort(snapshots[i].commitDate),
                added: diff.added.length,
                modified: diff.modified.length,
                removed: diff.removed.length
            });
        }

        if (state.timelineView === "recent") return entries.slice(-TIMELINE_RECENT_COUNT);
        if (state.timelineView === "all") return entries;

        var buckets = new Map();
        entries.forEach(function (entry) {
            var capturedAt = new Date(snapshots[entry.idx].commitDate);
            var periodStart;
            if (state.timelineView === "month") {
                periodStart = new Date(Date.UTC(capturedAt.getUTCFullYear(), capturedAt.getUTCMonth(), 1));
            } else {
                var daysSinceMonday = (capturedAt.getUTCDay() + 6) % 7;
                periodStart = new Date(Date.UTC(capturedAt.getUTCFullYear(), capturedAt.getUTCMonth(), capturedAt.getUTCDate() - daysSinceMonday));
            }
            var key = periodStart.toISOString().slice(0, 10);
            var bucket = buckets.get(key);
            if (!bucket) {
                bucket = {
                    idx: entry.idx,
                    startIdx: entry.idx,
                    endIdx: entry.idx,
                    captures: 0,
                    label: state.timelineView === "month"
                        ? periodStart.toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" })
                        : fmtDateShort(periodStart.toISOString()),
                    periodLabel: state.timelineView === "month"
                        ? periodStart.toLocaleDateString(undefined, { month: "long", year: "numeric", timeZone: "UTC" })
                        : "Week of " + fmtDateShort(periodStart.toISOString()),
                    added: 0,
                    modified: 0,
                    removed: 0
                };
                buckets.set(key, bucket);
            }
            bucket.idx = entry.idx;
            bucket.endIdx = entry.idx;
            bucket.captures += 1;
            bucket.added += entry.added;
            bucket.modified += entry.modified;
            bucket.removed += entry.removed;
        });
        return Array.from(buckets.values()).slice(-TIMELINE_RECENT_COUNT);
    }

    function renderTimeline() {
        var wrap = $("timelineChart");
        wrap.innerHTML = "";
        if (snapshots.length < 2) {
            wrap.innerHTML = '<div class="muted" style="padding:18px;">Only one snapshot in the dataset - changes over time appear here once a second snapshot is committed to the repository.</div>';
            return;
        }

        var entries = timelineEntries();
        var isAggregated = state.timelineView === "week" || state.timelineView === "month";
        $("timelineHint").textContent = isAggregated
            ? "Click a bar to inspect the latest snapshot captured in that period"
            : "Click a bar to inspect that snapshot's changes";

        var width = Math.max(280, wrap.clientWidth - 8);
        var height = 220, padL = 36, padB = 42, padT = 10, padR = 30;
        var innerW = width - padL - padR, innerH = height - padT - padB;
        var maxTotal = Math.max(1, d3.max(entries, function (e) { return e.added + e.modified + e.removed; }));
        var slotW = innerW / entries.length;
        var bw = Math.min(46, Math.max(3, slotW * 0.68));

        var svg = d3.create("svg").attr("width", width).attr("height", height);
        var x = function (i) { return padL + slotW * (i + 0.5); };
        var y = function (v) { return padT + innerH - (v / maxTotal) * innerH; };

        // y-axis gridlines
        [0, 0.5, 1].forEach(function (f) {
            var v = Math.round(maxTotal * f);
            svg.append("line").attr("x1", padL).attr("x2", width - padR).attr("y1", y(v)).attr("y2", y(v))
                .attr("stroke", "#edebe9");
            svg.append("text").attr("x", padL - 6).attr("y", y(v) + 3).attr("text-anchor", "end")
                .attr("font-size", 10).attr("fill", "#605e5c").text(v);
        });

        var tooltip = d3.select("#tooltip");
        entries.forEach(function (e, i) {
            var cx = x(i) - bw / 2;
            var segments = [
                { v: e.added, color: "#0e700e", label: "added" },
                { v: e.modified, color: "#c07807", label: "modified" },
                { v: e.removed, color: "#a4262c", label: "removed" }
            ];
            var acc = 0;
            var g = svg.append("g").style("cursor", "pointer");
            var total = e.added + e.modified + e.removed;
            segments.forEach(function (seg) {
                if (seg.v <= 0) return;
                var y1 = y(acc + seg.v), y2 = y(acc);
                g.append("rect").attr("x", cx).attr("y", y1).attr("width", bw)
                    .attr("height", Math.max(1, y2 - y1)).attr("fill", seg.color).attr("rx", 1.5);
                acc += seg.v;
            });
            if (total === 0) {
                g.append("rect").attr("x", cx).attr("y", y(0) - 2).attr("width", bw).attr("height", 2)
                    .attr("fill", "#d2d0ce").attr("rx", 1);
            }
            if (state.selectedIdx >= e.startIdx && state.selectedIdx <= e.endIdx) {
                g.append("rect").attr("x", cx - 3).attr("y", padT).attr("width", bw + 6).attr("height", innerH + 4)
                    .attr("fill", "none").attr("stroke", "#0078d4").attr("stroke-width", 1.5).attr("rx", 3);
            }
            // invisible hit area for easy clicking/tooltips
            g.append("rect").attr("x", cx - 3).attr("y", padT).attr("width", bw + 6).attr("height", innerH + 4)
                .attr("fill", "transparent")
                .on("mousemove", function (ev) {
                    tooltip.classed("hidden", false)
                        .style("left", (ev.clientX + 14) + "px").style("top", (ev.clientY + 14) + "px")
                        .html("<b>" + esc(isAggregated ? e.periodLabel : snapshotLabel(snapshots[e.idx], e.idx)) + "</b><br/>" +
                            (isAggregated ? e.captures + " snapshot" + (e.captures === 1 ? "" : "s") + " captured<br/>" : fmtDate(snapshots[e.idx].commitDate) + "<br/>") +
                            '<span style="color:#0e700e;">+' + e.added + " added</span> · " +
                            '<span style="color:#8a5a05;">~' + e.modified + " modified</span> · " +
                            '<span style="color:#a4262c;">−' + e.removed + " removed</span>");
                })
                .on("mouseleave", function () { tooltip.classed("hidden", true); })
                .on("click", function () { selectSnapshot(e.idx); });
        });

        // Place an evenly-spaced, endpoint-inclusive set of ticks. This avoids the old
        // "every N plus the final label" collision when the final two indices were adjacent.
        var maxTicks = Math.max(2, Math.floor(innerW / 88));
        var tickCount = Math.min(entries.length, maxTicks);
        var tickIndexes = new Set();
        for (var tick = 0; tick < tickCount; tick++) {
            tickIndexes.add(tickCount === 1 ? entries.length - 1 : Math.round(tick * (entries.length - 1) / (tickCount - 1)));
        }
        tickIndexes.forEach(function (index) {
            svg.append("text").attr("x", x(index)).attr("y", height - padB + 14).attr("text-anchor", "middle")
                .attr("font-size", 10).attr("fill", "#605e5c")
                .text(entries[index].label);
        });

        wrap.appendChild(svg.node());
    }

    // =====================================================================================
    // Snapshot changes / compare rendering
    // =====================================================================================
    function statusChip(status) {
        return '<span class="status-chip ' + status + '">' + status + "</span>";
    }

    function tierBadge(tierName) {
        var tiers = {
            ControlPlane: { label: "Control Plane", className: "tier-controlplane" },
            ManagementPlane: { label: "Management Plane", className: "tier-managementplane" },
            WorkloadPlane: { label: "Workload Plane", className: "tier-workloadplane" },
            UserAccess: { label: "User Access", className: "tier-useraccess" }
        };
        var tier = tiers[tierName] || { label: tierName || "Unclassified", className: "tier-unclassified" };
        return '<span class="tier-badge ' + tier.className + '">' + esc(tier.label) + "</span>";
    }

    // Shared change-row pipeline: the renderer and the CSV exporter must operate on the SAME
    // decorated rows and the SAME filter predicate so the export can never drift from the table.
    function buildChangeRows(base, cur) {
        var diff = diffSnapshots(base, cur, state.typeFilter);
        var allRows = [];
        diff.added.forEach(function (r) { allRows.push({ status: "added", r: r, baseHash: null, curHash: r.h }); });
        diff.modified.forEach(function (m) { allRows.push({ status: "modified", r: m.cur, baseHash: m.base.h, curHash: m.cur.h }); });
        diff.removed.forEach(function (r) { allRows.push({ status: "removed", r: r, baseHash: r.h, curHash: null }); });
        // Best-effort privileged-asset cross-reference (see relatedPrivilegedObjects).
        allRows.forEach(function (row) { row.privileged = relatedPrivilegedObjects(row.curHash || row.baseHash, row.r.type); });
        return { diff: diff, allRows: allRows };
    }

    function changeRowMatchesFilters(row) {
        if (!state.statusFilter.has(row.status)) return false;
        if (state.categoryFilter && (row.r.category || "(none)") !== state.categoryFilter) return false;
        if (state.privilegedOnly && !row.privileged) return false;
        if (state.tierFilter && (!row.privileged || !row.privileged.tierNames.has(state.tierFilter))) return false;
        if (state.classificationFilter && (!row.privileged || !row.privileged.services.has(state.classificationFilter))) return false;
        return true;
    }

    function renderChangeList(base, cur, container) {
        var typeFilter = state.typeFilter;
        var built = buildChangeRows(base, cur);
        var diff = built.diff;
        var allRows = built.allRows;
        var total = diff.added.length + diff.modified.length + diff.removed.length;

        if (total === 0) {
            container.innerHTML = '<div class="muted">No configuration changes between these snapshots' + (typeFilter ? " for resource type <code>" + esc(typeFilter) + "</code>" : "") + ".</div>";
            return;
        }

        var categories = {}, tierNames = {}, services = {};
        allRows.forEach(function (row) {
            categories[row.r.category || "(none)"] = true;
            if (!row.privileged) return;
            row.privileged.tierNames.forEach(function (t) { tierNames[t] = true; });
            row.privileged.services.forEach(function (s) { services[s] = true; });
        });
        if (state.categoryFilter && Object.keys(categories).indexOf(state.categoryFilter) === -1) state.categoryFilter = "";
        if (state.tierFilter && Object.keys(tierNames).indexOf(state.tierFilter) === -1) state.tierFilter = "";
        if (state.classificationFilter && Object.keys(services).indexOf(state.classificationFilter) === -1) state.classificationFilter = "";

        var rows = allRows.filter(changeRowMatchesFilters);
        var filtersActive = state.categoryFilter || state.privilegedOnly || state.tierFilter || state.classificationFilter || state.statusFilter.size < 3;

        var html = "";
        html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center;">';
        ["added", "modified", "removed"].forEach(function (s) {
            html += '<span class="status-chip ' + s + '" data-status-toggle="' + s + '" style="cursor:pointer;' +
                (state.statusFilter.has(s) ? "" : "opacity:.4;") + '" title="Click to show/hide ' + s + ' changes">' +
                diff[s].length + " " + s + "</span>";
        });
        html += '<span class="chip">' + cur.resources.length.toLocaleString() + " resources in current snapshot</span>";
        html += "</div>";

        html += '<div class="eam-filter-row" style="margin-bottom:6px;">';
        html += '<div class="eam-filter"><label>Category</label><select data-flt="category"><option value="">All categories</option>';
        Object.keys(categories).sort().forEach(function (c) {
            html += '<option value="' + esc(c) + '"' + (c === state.categoryFilter ? " selected" : "") + ">" + esc(c) + "</option>";
        });
        html += "</select></div>";
        if (objectTierIndex.size) {
            html += '<div class="eam-filter"><label>&nbsp;</label><span class="ca-toggle' + (state.privilegedOnly ? " on" : "") + '" data-flt="privilegedOnly">Privileged assets only</span></div>';
            html += '<div class="eam-filter"><label>Access tier</label><select data-flt="tier"><option value="">All tiers</option>';
            Object.keys(tierNames).sort().forEach(function (t) {
                html += '<option value="' + esc(t) + '"' + (t === state.tierFilter ? " selected" : "") + ">" + esc(t) + "</option>";
            });
            html += "</select></div>";
            html += '<div class="eam-filter"><label>Classification</label><select data-flt="classification"><option value="">All classifications</option>';
            Object.keys(services).sort().forEach(function (s) {
                html += '<option value="' + esc(s) + '"' + (s === state.classificationFilter ? " selected" : "") + ">" + esc(s) + "</option>";
            });
            html += "</select></div>";
        } else {
            html += '<div class="eam-filter grow"><label>&nbsp;</label><span class="muted" style="font-size:12px;">Generate <code>Reports/EamDashboard/data/eam-dashboard-data.js</code> (New-EntraOpsPrivilegedEamDashboardData) to filter by privileged asset / access tier / classification.</span></div>';
        }
        if (filtersActive) {
            html += '<div class="eam-filter" style="align-self:flex-end;"><button class="btn small" data-flt="clear">Clear filters</button></div>';
        }
        html += "</div>";

        if (filtersActive) {
            html += '<p class="muted" style="font-size:12px;margin-bottom:8px;">Showing ' + rows.length.toLocaleString() + " of " + allRows.length.toLocaleString() + " change(s).</p>";
        }

        if (!rows.length) {
            html += '<div class="muted">No changes match the current filters.</div>';
            container.innerHTML = html;
            wireChangeListFilters(container, base, cur);
            return;
        }

        html += '<div class="table-wrap change-table-wrap"><table class="grid-table"><thead><tr>' +
            '<th class="no-sort">Status</th><th class="no-sort">Resource type</th><th class="no-sort">Category</th><th class="no-sort">Name</th><th class="no-sort">Privileged asset</th>' +
            "</tr></thead><tbody>";
        rows.forEach(function (row, i) {
            var privHtml = row.privileged
                ? Array.from(row.privileged.tierNames).map(tierBadge).join(" ")
                : "";
            html += '<tr data-row="' + i + '">' +
                '<td><span data-status-flt="' + esc(row.status) + '" style="cursor:pointer;">' + statusChip(row.status) + "</span></td>" +
                '<td><code data-type-flt="' + esc(row.r.type) + '" style="cursor:pointer;">' + esc(row.r.type) + "</code></td>" +
                '<td><span data-cat-flt="' + esc(row.r.category || "(none)") + '" style="cursor:pointer;">' + esc(row.r.category || "(none)") + "</span></td>" +
                "<td>" + esc(row.r.name) + "</td>" +
                "<td>" + privHtml + "</td>" +
                "</tr>";
            html += '<tr class="hidden" data-detail="' + i + '"><td colspan="5"></td></tr>';
        });
        html += "</tbody></table></div>";
        html += '<p class="muted" style="font-size:12px;margin-top:8px;">Click a row to see the property-level diff (available when both snapshots embed resource content - see <code>-MaxDetailedSnapshots</code>). Click a status, resource type or category value to filter by it.</p>';
        container.innerHTML = html;

        container.querySelectorAll("tr[data-row]").forEach(function (tr) {
            tr.addEventListener("click", function () {
                var i = Number(tr.getAttribute("data-row"));
                var detailRow = container.querySelector('tr[data-detail="' + i + '"]');
                if (!detailRow.classList.contains("hidden")) { detailRow.classList.add("hidden"); return; }
                detailRow.querySelector("td").innerHTML = renderResourceDiffDetail(rows[i]);
                detailRow.classList.remove("hidden");
            });
        });

        wireChangeListFilters(container, base, cur);
    }

    // Wires the filter row + clickable status/type/category values rendered by
    // renderChangeList. Re-invokes renderChangeList (closing over base/cur/container) after
    // any filter change, so this section always reflects the shared filter state.
    function wireChangeListFilters(container, base, cur) {
        container.querySelectorAll("[data-status-toggle]").forEach(function (el) {
            el.addEventListener("click", function () {
                var s = el.getAttribute("data-status-toggle");
                if (state.statusFilter.has(s)) state.statusFilter.delete(s); else state.statusFilter.add(s);
                renderChangeList(base, cur, container);
            });
        });
        container.querySelectorAll("[data-status-flt]").forEach(function (el) {
            el.addEventListener("click", function (ev) {
                ev.stopPropagation();
                var s = el.getAttribute("data-status-flt");
                state.statusFilter = new Set([s]);
                renderChangeList(base, cur, container);
            });
        });
        container.querySelectorAll("[data-type-flt]").forEach(function (el) {
            el.addEventListener("click", function (ev) {
                ev.stopPropagation();
                state.typeFilter = el.getAttribute("data-type-flt");
                asrState.type = state.typeFilter;
                asrState.selectedPath = "";
                asrState.expandedProducts = new Set();
                asrState.expandedFamilies = new Set();
                renderTypeFilter();
                renderTimeline();
                renderAllSnapshotResources();
                renderChangeList(base, cur, container);
            });
        });
        container.querySelectorAll("[data-cat-flt]").forEach(function (el) {
            el.addEventListener("click", function (ev) {
                ev.stopPropagation();
                state.categoryFilter = el.getAttribute("data-cat-flt");
                renderChangeList(base, cur, container);
            });
        });
        var catSel = container.querySelector('select[data-flt="category"]');
        if (catSel) catSel.addEventListener("change", function () { state.categoryFilter = this.value; renderChangeList(base, cur, container); });
        var tierSel = container.querySelector('select[data-flt="tier"]');
        if (tierSel) tierSel.addEventListener("change", function () { state.tierFilter = this.value; renderChangeList(base, cur, container); });
        var classSel = container.querySelector('select[data-flt="classification"]');
        if (classSel) classSel.addEventListener("change", function () { state.classificationFilter = this.value; renderChangeList(base, cur, container); });
        var privToggle = container.querySelector('[data-flt="privilegedOnly"]');
        if (privToggle) privToggle.addEventListener("click", function () { state.privilegedOnly = !state.privilegedOnly; renderChangeList(base, cur, container); });
        var clearBtn = container.querySelector('[data-flt="clear"]');
        if (clearBtn) clearBtn.addEventListener("click", function () {
            state.categoryFilter = ""; state.privilegedOnly = false; state.tierFilter = ""; state.classificationFilter = "";
            state.statusFilter = new Set(["added", "modified", "removed"]);
            renderChangeList(base, cur, container);
        });
    }

    function hasOwn(value, key) {
        return value !== null && typeof value === "object" && Object.prototype.hasOwnProperty.call(value, key);
    }

    function propertyReference(value) {
        if (typeof value !== "string" || !value.trim()) return null;
        var identity = classifiedObjectForReference(value);
        if (identity && identity.objectId) {
            return {
                label: identity.displayName || identity.userPrincipalName || value,
                href: "../EamDashboard/index.html#asset=" + encodeURIComponent(identity.objectId)
            };
        }
        var snapshotIndex = typeof paState !== "undefined" && paState && paState.snapshotIdx >= 0 ? paState.snapshotIdx : state.selectedIdx;
        var snapshot = snapshots[snapshotIndex];
        if (!snapshot) return null;
        var wanted = value.trim().toUpperCase();
        // Lazily-built per-snapshot identity index (UPPER(Id|id|DisplayName|Name|name) -> first
        // matching resource). Without it every rendered string leaf linearly re-scanned all blobs.
        if (!snapshot.__identityIndex) {
            var identityIndex = new Map();
            snapshot.resources.forEach(function (item) {
                var blob = blobContent(item.h);
                var properties = blob && blob.properties;
                if (!properties) return;
                [properties.Id, properties.id, properties.DisplayName, properties.Name, item.name].forEach(function (candidate) {
                    if (candidate == null) return;
                    var key = String(candidate).trim().toUpperCase();
                    if (key && !identityIndex.has(key)) identityIndex.set(key, item);
                });
            });
            snapshot.__identityIndex = identityIndex;
        }
        var resource = snapshot.__identityIndex.get(wanted);
        if (!resource) return null;
        var resourceBlob = blobContent(resource.h) || {};
        var resourceProperties = resourceBlob.properties || {};
        return {
            label: resourceProperties.DisplayName || resourceProperties.Name || resource.name || value,
            href: "index.html?view=privileged" + configurationObjectDeepLink(snapshotIndex, resource.p)
        };
    }

    function propertyValue(value) {
        if (value === undefined) return "<i>(not set)</i>";
        if (value === null) return "null";
        var reference = propertyReference(value);
        if (reference) return '<a href="' + esc(reference.href) + '">' + esc(reference.label) + "</a>";
        return esc(typeof value === "object" ? JSON.stringify(value) : String(value));
    }

    function propertyEntryLabel(value, index) {
        if (value == null) return "Item " + (index + 1);
        if (typeof value !== "object" || Array.isArray(value)) return String(value);
        var identifier = value.DisplayName || value.displayName || value.ObjectDisplayName || value.objectDisplayName ||
            value.Name || value.name || value.Identity || value.identity || value.UserPrincipalName || value.userPrincipalName ||
            value.RoleDisplayName || value.roleDisplayName || value.Id || value.id || value.ObjectId || value.objectId;
        var type = value.Type || value.type || value.ObjectType || value.objectType;
        if (identifier && type && String(identifier).toLowerCase() !== String(type).toLowerCase()) return identifier + " · " + type;
        return identifier || type || "Item " + (index + 1);
    }

    function propertyTreeChildren(baseValue, hasBase, currentValue, hasCurrent, mode, depth) {
        if (!hasBase && !hasCurrent) return "";
        if (!hasBase && hasCurrent && !isPrimitive(currentValue)) {
            return propertyTreeChildren(currentValue, true, currentValue, true, mode === "modified" ? "added" : mode, depth);
        }
        if (hasBase && !hasCurrent && !isPrimitive(baseValue)) {
            return propertyTreeChildren(baseValue, true, baseValue, true, mode === "modified" ? "removed" : mode, depth);
        }
        var basePrimitive = !hasBase || isPrimitive(baseValue);
        var currentPrimitive = !hasCurrent || isPrimitive(currentValue);
        if (basePrimitive && currentPrimitive) {
            if (mode === "modified" && hasBase && hasCurrent && baseValue === currentValue) return "";
            if (mode === "modified") {
                return '<div class="ca-property-leaf"><span class="old">' + propertyValue(baseValue) + '</span><span class="new">' + propertyValue(currentValue) + '</span></div>';
            }
            return '<div class="ca-property-leaf ' + (mode === "added" ? "new" : "old") + '">' + propertyValue(mode === "added" ? currentValue : baseValue) + '</div>';
        }
        if (basePrimitive !== currentPrimitive || (hasBase && hasCurrent && Array.isArray(baseValue) !== Array.isArray(currentValue))) {
            if (mode === "modified" && JSON.stringify(baseValue) === JSON.stringify(currentValue)) return "";
            return '<div class="ca-property-leaf"><span class="old">' + propertyValue(baseValue) + '</span><span class="new">' + propertyValue(currentValue) + '</span></div>';
        }
        var isArray = Array.isArray(hasCurrent ? currentValue : baseValue);
        var sourceBase = hasBase ? baseValue : (isArray ? [] : {});
        var sourceCurrent = hasCurrent ? currentValue : (isArray ? [] : {});
        var keys = isArray ? [] : Object.keys(sourceBase).concat(Object.keys(sourceCurrent)).filter(function (key, index, values) { return values.indexOf(key) === index; }).sort();
        if (isArray) {
            var length = Math.max(sourceBase.length, sourceCurrent.length);
            for (var index = 0; index < length; index++) keys.push(String(index));
        }
        if (!keys.length) {
            if (mode === "modified" && hasBase && hasCurrent && JSON.stringify(baseValue) === JSON.stringify(currentValue)) return "";
            return '<div class="ca-property-leaf muted ' + (mode === "added" ? "new" : mode === "removed" ? "old" : "") + '">' + (isArray ? "No entries" : "No fields") + '</div>';
        }
        var children = "";
        keys.forEach(function (key) {
            var keyBase = isArray ? Number(key) < sourceBase.length : hasOwn(sourceBase, key);
            var keyCurrent = isArray ? Number(key) < sourceCurrent.length : hasOwn(sourceCurrent, key);
            var child = propertyTreeChildren(sourceBase[key], keyBase, sourceCurrent[key], keyCurrent, mode, depth + 1);
            if (!child) return;
            var childValue = keyCurrent ? sourceCurrent[key] : sourceBase[key];
            var label = isArray ? propertyEntryLabel(childValue, Number(key)) : key;
            var childIsArray = (keyCurrent && Array.isArray(sourceCurrent[key])) || (keyBase && Array.isArray(sourceBase[key]));
            var childIsObject = (keyCurrent && !isPrimitive(sourceCurrent[key])) || (keyBase && !isPrimitive(sourceBase[key]));
            if (childIsObject) {
                var count = childIsArray ? Math.max(keyBase && sourceBase[key] ? sourceBase[key].length : 0, keyCurrent && sourceCurrent[key] ? sourceCurrent[key].length : 0) : Object.keys(keyCurrent ? sourceCurrent[key] : sourceBase[key]).length;
                children += '<details class="ca-property-node' + (childIsArray ? " is-array" : " is-object") + '"' + (depth < 2 ? " open" : "") + '><summary><span class="ca-property-label">' + esc(label) + '</span><span class="ca-property-count">' + (childIsArray ? "Items" : "Fields") + " · " + count + '</span></summary><div class="ca-property-children">' + child + "</div></details>";
            } else {
                children += '<div class="ca-property-item"><span>' + esc(label) + "</span>" + child + "</div>";
            }
        });
        return children;
    }

    function renderPropertyTree(baseValue, hasBase, currentValue, hasCurrent, mode) {
        var body = propertyTreeChildren(baseValue, hasBase, currentValue, hasCurrent, mode, 0);
        return body ? '<div class="ca-property-tree">' + body + "</div>" : '<div class="muted">No property-level differences were found.</div>';
    }

    function renderResourceDiffDetail(row, view) {
        var baseObj = row.baseHash ? blobContent(row.baseHash) : null;
        var curObj = row.curHash ? blobContent(row.curHash) : null;

        if (view === "tree") {
            if (row.status === "modified") {
                if (baseObj === undefined || curObj === undefined) {
                    return '<div class="muted">Resource content is not embedded for one or both of these snapshots. Regenerate with a higher <code>-MaxDetailedSnapshots</code> to include it.</div>';
                }
                if (baseObj === null || curObj === null) {
                    return '<div class="muted">Resource content could not be parsed as JSON for one or both snapshots.</div>';
                }
                return renderPropertyTree(baseObj, true, curObj, true, "modified");
            }
            var treeObject = row.status === "added" ? curObj : baseObj;
            if (treeObject === undefined) return '<div class="muted">Resource content is not embedded for this snapshot.</div>';
            if (treeObject === null) return '<div class="muted">Resource content could not be parsed as JSON.</div>';
            return renderPropertyTree(baseObj, row.status === "removed", curObj, row.status === "added", row.status);
        }

        if (row.status === "modified") {
            if (baseObj === undefined || curObj === undefined) {
                return '<div class="muted">Resource content is not embedded for one or both of these snapshots. Regenerate with a higher <code>-MaxDetailedSnapshots</code> to include it.</div>';
            }
            if (baseObj === null || curObj === null) {
                return '<div class="muted">Resource content could not be parsed as JSON for one or both snapshots.</div>';
            }
            var rows = propertyDiff(baseObj, curObj);
            if (!rows.length) return '<div class="muted">Content hash changed but no property-level differences were found (e.g. formatting only).</div>';
            var html = '<table class="ca-diff-table"><thead><tr><th style="width:34%;">Property</th><th style="width:33%;">Baseline</th><th style="width:33%;">Current</th></tr></thead><tbody>';
            rows.forEach(function (d) {
                html += "<tr><td class='prop'>" + esc(d.key) + "</td>" +
                    "<td class='old'>" + (d.old === undefined ? "<i>(not set)</i>" : esc(d.old)) + "</td>" +
                    "<td class='new'>" + (d.new === undefined ? "<i>(removed)</i>" : esc(d.new)) + "</td></tr>";
            });
            html += "</tbody></table>";
            return html;
        }

        // added / removed: show the flattened content of the side that exists
        var obj = row.status === "added" ? curObj : baseObj;
        if (obj === undefined) return '<div class="muted">Resource content is not embedded for this snapshot.</div>';
        if (obj === null) return '<div class="muted">Resource content could not be parsed as JSON.</div>';
        var flat = flatten(obj, "", {});
        var keys = Object.keys(flat).sort();
        var html2 = '<table class="ca-diff-table"><thead><tr><th style="width:40%;">Property</th><th>Value</th></tr></thead><tbody>';
        keys.forEach(function (k) {
            html2 += "<tr><td class='prop'>" + esc(k) + "</td><td class='" + (row.status === "added" ? "new" : "old") + "'>" + esc(flat[k]) + "</td></tr>";
        });
        html2 += "</tbody></table>";
        return html2;
    }

    function selectSnapshot(idx) {
        state.selectedIdx = idx;
        renderTimeline();
        var chip = $("changesChip");
        chip.classList.remove("hidden");
        chip.textContent = snapshotLabel(snapshots[idx], idx) + " vs. " + snapshotLabel(snapshots[idx - 1], idx - 1);
        renderChangeList(snapshots[idx - 1], snapshots[idx], $("changesBody"));
        if (asrState.snapshotIdx !== idx) setExplorerSnapshot(idx, false);
        $("secChanges").scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function exportChangeRows(base, current) {
        if (!base || !current) return [];
        // Same row pipeline and filter predicate as renderChangeList - exports exactly the
        // rows the table currently displays.
        return buildChangeRows(base, current).allRows.filter(changeRowMatchesFilters).map(function (row) {
            return { baseline: snapshotLabel(base, snapshots.indexOf(base)), current: snapshotLabel(current, snapshots.indexOf(current)), status: row.status, resourceType: row.r.type, category: row.r.category || "", name: row.r.name, path: row.r.p, privilegedTiers: row.privileged ? Array.from(row.privileged.tierNames).join("; ") : "", classifications: row.privileged ? Array.from(row.privileged.services).join("; ") : "" };
        });
    }

    function renderCompareSelects() {
        var base = $("cmpBaseline"), cur = $("cmpCurrent");
        var html = "";
        snapshots.forEach(function (s, i) {
            html += '<option value="' + i + '">' + esc(snapshotLabel(s, i)) + (s.hasDetail ? " ✓ content" : "") + "</option>";
        });
        base.innerHTML = html;
        cur.innerHTML = html;
        base.value = "0";
        cur.value = String(snapshots.length - 1);
    }

    // =====================================================================================
    // Snapshot Resources
    // =====================================================================================
    var asrState = {
        snapshotIdx: -1, type: "", category: "", changeMode: "all", search: "", selectedPath: "",
        baselineIdx: -1, currentIdx: -1, privilegedOnly: false, tierFilter: "", classificationFilter: "",
        propertyView: "tree", expandedProducts: new Set(), expandedFamilies: new Set()
    };

    var ASR_PRODUCT_META = {
        "microsoft.entra": { label: "Microsoft.Entra", icon: "&#128273;", className: "entra" },
        "microsoft.intune": { label: "Microsoft.Intune", icon: "&#128736;&#65039;", className: "intune" },
        "microsoft.azure": { label: "Microsoft.Azure", icon: "&#9729;&#65039;", className: "azure" },
        "microsoft.defender": { label: "Microsoft.Defender", icon: "&#128737;&#65039;", className: "defender" }
    };
    var ASR_FAMILY_PREFIXES = [
        ["authenticationmethodpolicy", "AuthenticationMethodPolicy"],
        ["crosstenantaccesspolicy", "CrossTenantAccessPolicy"],
        ["entitlementmanagement", "EntitlementManagement"],
        ["devicecompliancepolicy", "DeviceCompliancePolicy"],
        ["deviceconfiguration", "DeviceConfiguration"],
        ["deviceenrollment", "DeviceEnrollment"],
        ["authenticationstrengthpolicy", "AuthenticationStrengthPolicy"],
        ["conditionalaccesspolicy", "ConditionalAccessPolicy"],
        ["securitydefaults", "SecurityDefaults"]
    ];

    function asrTypeHierarchy(resourceType) {
        var parts = String(resourceType || "unknown").split(".");
        var productKey = parts.slice(0, 2).join(".").toLowerCase();
        var suffix = parts.slice(2).join(".") || parts[parts.length - 1] || "Other";
        var family = suffix.charAt(0).toUpperCase() + suffix.slice(1);
        ASR_FAMILY_PREFIXES.some(function (entry) {
            if (suffix.toLowerCase().indexOf(entry[0]) !== 0) return false;
            family = entry[1];
            return true;
        });
        var product = ASR_PRODUCT_META[productKey] || { label: parts.slice(0, 2).join(".") || "Other", icon: "&#9638;", className: "other" };
        return { productKey: productKey, product: product, family: family, familyKey: productKey + "|" + family };
    }

    // Per-snapshot path -> resource index. Snapshots are static data, so each map is built once
    // lazily and cached on the snapshot object; without this, asrResourceStatus's linear scans
    // made every Snapshot Resources render (incl. each search keystroke) O(resources^2).
    function snapshotResourceByPath(snapshot) {
        if (!snapshot) return null;
        if (!snapshot.__resourceByPath) {
            var map = new Map();
            // First-writer-wins mirrors the previous filter(...)[0] first-match semantics.
            snapshot.resources.forEach(function (resource) { if (!map.has(resource.p)) map.set(resource.p, resource); });
            snapshot.__resourceByPath = map;
        }
        return snapshot.__resourceByPath;
    }

    function asrResourceStatus(path) {
        var baselineMap = snapshotResourceByPath(snapshots[asrState.baselineIdx]);
        var currentMap = snapshotResourceByPath(snapshots[asrState.snapshotIdx]);
        var baseResource = baselineMap && baselineMap.get(path);
        var currentResource = currentMap && currentMap.get(path);
        if (!baseResource && currentResource) return "added";
        if (baseResource && !currentResource) return "removed";
        return baseResource && currentResource && baseResource.h !== currentResource.h ? "modified" : "unchanged";
    }

    function asrListResources() {
        var snapshot = snapshots[asrState.changeMode === "removed" ? asrState.baselineIdx : asrState.snapshotIdx];
        return snapshot ? snapshot.resources : [];
    }

    function asrPrivilege(resource) {
        return relatedPrivilegedObjects(resource.h, resource.type);
    }

    function asrMatchesFilters(resource) {
        var query = asrState.search.trim().toLowerCase();
        var status = asrResourceStatus(resource.p);
        var privileged = asrPrivilege(resource);
        var modeMatches = asrState.changeMode === "all" ||
            (asrState.changeMode === "changed" && status !== "unchanged") || status === asrState.changeMode;
        return (!asrState.type || resource.type === asrState.type) &&
            (!asrState.category || (resource.category || "(none)") === asrState.category) && modeMatches &&
            (!query || [resource.name, resource.category, resource.type].join(" ").toLowerCase().indexOf(query) !== -1) &&
            (!asrState.privilegedOnly || !!privileged) &&
            (!asrState.tierFilter || (privileged && privileged.tierNames.has(asrState.tierFilter))) &&
            (!asrState.classificationFilter || (privileged && privileged.services.has(asrState.classificationFilter)));
    }

    function asrFilteredResources() {
        return asrListResources().filter(asrMatchesFilters).sort(function (a, b) { return a.p.localeCompare(b.p); });
    }

    function asrHistory(path) {
        var present = 0, changed = 0, firstSeen = -1, lastChanged = -1, previousHash;
        snapshots.forEach(function (snapshot, index) {
            var resource = snapshotResourceByPath(snapshot).get(path);
            if (!resource) return;
            present++;
            if (firstSeen < 0) firstSeen = index;
            if (previousHash !== undefined && previousHash !== resource.h) { changed++; lastChanged = index; }
            previousHash = resource.h;
        });
        return { present: present, changed: changed, firstSeen: firstSeen, lastChanged: lastChanged };
    }

    function setExplorerSnapshot(idx, syncTimeline) {
        asrState.snapshotIdx = idx;
        asrState.currentIdx = idx;
        asrState.baselineIdx = idx > 0 ? idx - 1 : -1;
        asrState.selectedPath = "";
        asrState.expandedProducts = new Set();
        asrState.expandedFamilies = new Set();
        if (syncTimeline) {
            state.selectedIdx = idx;
            renderTimeline();
            var chip = $("changesChip");
            if (idx > 0) {
                chip.classList.remove("hidden");
                chip.textContent = snapshotLabel(snapshots[idx], idx) + " vs. " + snapshotLabel(snapshots[idx - 1], idx - 1);
                renderChangeList(snapshots[idx - 1], snapshots[idx], $("changesBody"));
            } else {
                chip.classList.add("hidden");
                chip.textContent = "";
                $("changesBody").innerHTML = '<div class="muted">The first snapshot has no previous snapshot to compare against - click a bar in the timeline above to inspect a later snapshot.</div>';
            }
        }
        renderAllSnapshotResources();
    }

    function asrResourceGroups(resources) {
        var products = {};
        resources.forEach(function (resource) {
            var hierarchy = asrTypeHierarchy(resource.type);
            if (!products[hierarchy.productKey]) products[hierarchy.productKey] = { key: hierarchy.productKey, meta: hierarchy.product, families: {} };
            if (!products[hierarchy.productKey].families[hierarchy.familyKey]) products[hierarchy.productKey].families[hierarchy.familyKey] = { key: hierarchy.familyKey, name: hierarchy.family, resources: [] };
            products[hierarchy.productKey].families[hierarchy.familyKey].resources.push(resource);
        });
        return Object.keys(products).sort().map(function (productKey) {
            var product = products[productKey];
            product.families = Object.keys(product.families).sort().map(function (familyKey) { return product.families[familyKey]; });
            return product;
        });
    }

    function asrHighlight(value) {
        var text = String(value == null ? "" : value);
        var query = asrState.search.trim();
        if (!query) return esc(text);
        var expression = new RegExp("(" + query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
        // Highlight inside the escaped text, but never inside an HTML entity (&amp; / &#39; / ...):
        // searching "amp", "quot" or "lt" would otherwise corrupt the entity markup. Even-indexed
        // split segments are plain text, odd-indexed segments are whole entities.
        return esc(text).split(/(&(?:[a-zA-Z][a-zA-Z0-9]*|#\d+|#[xX][0-9a-fA-F]+);)/).map(function (segment, index) {
            if (index % 2 === 1) return segment;
            expression.lastIndex = 0;
            return segment.replace(expression, "<mark>$1</mark>");
        }).join("");
    }

    function renderAsrDetail() {
        var container = $("asrDetail");
        var selected = asrListResources().filter(function (resource) { return resource.p === asrState.selectedPath; })[0];
        if (!selected) {
            container.innerHTML = '<div class="muted asr-empty">Select a resource to inspect its properties and compare it across snapshots.</div>';
            return;
        }
        var resources = asrFilteredResources();
        var selectedIndex = resources.findIndex(function (resource) { return resource.p === selected.p; });
        var baseline = snapshots[asrState.baselineIdx];
        var current = snapshots[asrState.currentIdx];
        var baselineResource = baseline && snapshotResourceByPath(baseline).get(selected.p);
        var currentResource = current && snapshotResourceByPath(current).get(selected.p);
        var history = asrHistory(selected.p);
        var currentLabel = currentResource ? snapshotLabel(snapshots[asrState.currentIdx], asrState.currentIdx) : "Not present";
        var detailHtml = '<div class="asr-detail-path"><span>Snapshot resources</span><b>/</b><span>' + esc(selected.type) + '</span><b>/</b><strong>' + esc(selected.name) + '</strong></div>' +
            '<div class="asr-detail-head"><div><strong>' + esc(selected.name) + '</strong><div class="muted"><code>' + esc(selected.type) + '</code>' + (selected.category ? ' · ' + esc(selected.category) : '') + '</div></div>' +
            '<div class="asr-nav"><button class="btn small" data-asr-open-details>Open details</button><button class="btn small" data-asr-open-diff' + (asrState.snapshotIdx <= 0 ? ' disabled' : '') + '>Open change diff</button><button class="btn small" data-asr-nav="previous"' + (selectedIndex <= 0 ? ' disabled' : '') + '>Previous</button><button class="btn small" data-asr-nav="next"' + (selectedIndex < 0 || selectedIndex >= resources.length - 1 ? ' disabled' : '') + '>Next</button></div></div>' +
            '<div class="asr-resource-meta"><div><span>Resource type</span><strong>' + esc(selected.type) + '</strong></div><div><span>Category</span><strong>' + esc(selected.category || 'Uncategorized') + '</strong></div><div><span>Current snapshot</span><strong>' + esc(currentLabel) + '</strong></div></div>' +
            '<div class="asr-history"><div><span>First seen</span><strong>' + esc(history.firstSeen >= 0 ? fmtDateShort(snapshots[history.firstSeen].commitDate) : "-") + '</strong></div><div><span>Last changed</span><strong>' + esc(history.lastChanged >= 0 ? fmtDateShort(snapshots[history.lastChanged].commitDate) : "No content change") + '</strong></div><div><span>Present in</span><strong>' + history.present + ' snapshot(s)</strong></div><div><span>Content changes</span><strong>' + history.changed + '</strong></div></div>';
        detailHtml += '<div class="eam-filter-row asr-compare-controls"><div class="eam-filter"><label for="asrBaseline">Baseline</label><select id="asrBaseline">';
        detailHtml += '<option value="">Select a baseline snapshot</option>';
        snapshots.forEach(function (snapshot, index) { detailHtml += '<option value="' + index + '"' + (index === asrState.baselineIdx ? ' selected' : '') + '>' + esc(snapshotLabel(snapshot, index)) + '</option>'; });
        detailHtml += '</select></div><div class="eam-filter"><label for="asrCurrent">Current</label><select id="asrCurrent">';
        detailHtml += '<option value="">Select a current snapshot</option>';
        snapshots.forEach(function (snapshot, index) { detailHtml += '<option value="' + index + '"' + (index === asrState.currentIdx ? ' selected' : '') + '>' + esc(snapshotLabel(snapshot, index)) + '</option>'; });
        detailHtml += '</select></div><div class="eam-filter asr-property-controls"><label>Properties</label><div><button class="btn small' + (asrState.propertyView === "tree" ? " primary" : "") + '" data-asr-property-view="tree">Grouped</button><button class="btn small' + (asrState.propertyView === "flat" ? " primary" : "") + '" data-asr-property-view="flat">Flat list</button><button class="btn small" data-asr-property-expand="true">Expand all</button><button class="btn small" data-asr-property-expand="false">Collapse all</button></div></div></div>';
        if (asrState.baselineIdx < 0 || asrState.currentIdx < 0) {
            detailHtml += '<div class="muted">Select a baseline and current snapshot to compare this resource.</div>' +
                renderResourceDiffDetail({ status: "added", curHash: selected.h }, asrState.propertyView);
        } else if (!baselineResource && !currentResource) {
            detailHtml += '<div class="muted">This resource is not present in either selected snapshot.</div>';
        } else if (!baselineResource) {
            detailHtml += '<div class="asr-status added">Added in the selected current snapshot.</div>' + renderResourceDiffDetail({ status: "added", curHash: currentResource.h }, asrState.propertyView);
        } else if (!currentResource) {
            detailHtml += '<div class="asr-status removed">Removed before the selected current snapshot.</div>' + renderResourceDiffDetail({ status: "removed", baseHash: baselineResource.h }, asrState.propertyView);
        } else if (baselineResource.h === currentResource.h) {
            detailHtml += '<div class="asr-status unchanged">No property changes between the selected snapshots. Showing current content.</div>' + renderResourceDiffDetail({ status: "added", curHash: currentResource.h }, asrState.propertyView);
        } else {
            detailHtml += '<div class="asr-status modified">Modified between the selected snapshots.</div>' + renderResourceDiffDetail({ status: "modified", baseHash: baselineResource.h, curHash: currentResource.h }, asrState.propertyView);
        }
        container.innerHTML = detailHtml;
        container.querySelectorAll("[data-asr-nav]").forEach(function (button) {
            button.addEventListener("click", function () {
                var nextIndex = selectedIndex + (button.getAttribute("data-asr-nav") === "next" ? 1 : -1);
                asrState.selectedPath = resources[nextIndex].p;
                renderAllSnapshotResources();
            });
        });
        var openDetails = container.querySelector("[data-asr-open-details]");
        if (openDetails) openDetails.addEventListener("click", function () { openSnapshotResourceDetails(currentResource || selected); });
        var openDiff = container.querySelector("[data-asr-open-diff]");
        if (openDiff) openDiff.addEventListener("click", function () {
            if (asrState.snapshotIdx <= 0) return;
            if (configurationView() !== "configuration") {
                // #secChanges is hidden outside the default configuration view - switch back
                // to it (same mechanism as the "Compare type history" button) before scrolling.
                // window.history: renderAsrDetail's local "history" variable shadows the global.
                window.history.pushState(null, "", location.pathname);
                applyConfigurationView();
            }
            selectSnapshot(asrState.snapshotIdx);
            $("secChanges").scrollIntoView({ behavior: "smooth", block: "start" });
        });
        $("asrBaseline").addEventListener("change", function () { asrState.baselineIdx = this.value === "" ? -1 : Number(this.value); renderAllSnapshotResources(); });
        $("asrCurrent").addEventListener("change", function () { asrState.currentIdx = this.value === "" ? -1 : Number(this.value); renderAllSnapshotResources(); });
        container.querySelectorAll("[data-asr-property-view]").forEach(function (button) {
            button.addEventListener("click", function () { asrState.propertyView = button.getAttribute("data-asr-property-view"); renderAsrDetail(); });
        });
        container.querySelectorAll("[data-asr-property-expand]").forEach(function (button) {
            button.addEventListener("click", function () {
                container.querySelectorAll(".ca-property-node").forEach(function (node) { node.open = button.getAttribute("data-asr-property-expand") === "true"; });
            });
        });
    }

    function renderAllSnapshotResources() {
        var snapshot = snapshots[asrState.snapshotIdx];
        var snapshotSelect = $("asrSnapshot"), typeSelect = $("asrType"), list = $("asrList");
        snapshotSelect.innerHTML = snapshots.map(function (item, index) {
            var subject = item.subject ? " · " + truncate(item.subject, 52) : "";
            return '<option value="' + index + '"' + (index === asrState.snapshotIdx ? ' selected' : '') + '>' + esc(snapshotLabel(item, index) + " · " + item.resources.length + " resources" + (item.hasDetail ? " · content" : "") + subject) + '</option>';
        }).join("");
        var allResources = asrListResources();
        var types = allResources.map(function (resource) { return resource.type; }).filter(function (type, index, values) { return values.indexOf(type) === index; }).sort();
        if (types.indexOf(asrState.type) === -1) asrState.type = "";
        typeSelect.innerHTML = '<option value="">All resource types</option>' + types.map(function (type) {
            return '<option value="' + esc(type) + '"' + (type === asrState.type ? ' selected' : '') + '>' + esc(type) + '</option>';
        }).join("");

        var categories = allResources.filter(function (resource) { return !asrState.type || resource.type === asrState.type; })
            .map(function (resource) { return resource.category || "(none)"; }).filter(function (category, index, values) { return values.indexOf(category) === index; }).sort();
        if (categories.indexOf(asrState.category || "(none)") === -1) asrState.category = "";
        $("asrCategory").innerHTML = '<option value="">All categories</option>' + categories.map(function (category) {
            return '<option value="' + esc(category) + '"' + (asrState.category === category ? ' selected' : '') + '>' + esc(category) + '</option>';
        }).join("");
        $("asrChangeMode").value = asrState.changeMode;

        var privilegeContexts = allResources.map(asrPrivilege).filter(Boolean);
        var tiers = {}, classifications = {};
        privilegeContexts.forEach(function (context) {
            context.tierNames.forEach(function (tier) { tiers[tier] = true; });
            context.services.forEach(function (service) { classifications[service] = true; });
        });
        if (asrState.tierFilter && Object.keys(tiers).indexOf(asrState.tierFilter) === -1) asrState.tierFilter = "";
        if (asrState.classificationFilter && Object.keys(classifications).indexOf(asrState.classificationFilter) === -1) asrState.classificationFilter = "";
        if (objectTierIndex.size) {
            $("asrPrivilegedToggle").innerHTML = '<label class="check-label"><input type="checkbox" id="asrPrivilegedOnly"' + (asrState.privilegedOnly ? ' checked' : '') + ' /> Privileged assets only</label>';
            $("asrTierFilter").innerHTML = '<label for="asrTier">Access tier</label><select id="asrTier"><option value="">All tiers</option>' + Object.keys(tiers).sort().map(function (tier) { return '<option value="' + esc(tier) + '"' + (tier === asrState.tierFilter ? ' selected' : '') + '>' + esc(tier) + '</option>'; }).join("") + '</select>';
            $("asrClassificationFilter").innerHTML = '<label for="asrClassification">Classification</label><select id="asrClassification"><option value="">All classifications</option>' + Object.keys(classifications).sort().map(function (service) { return '<option value="' + esc(service) + '"' + (service === asrState.classificationFilter ? ' selected' : '') + '>' + esc(service) + '</option>'; }).join("") + '</select>';
        } else {
            $("asrPrivilegedToggle").innerHTML = '<span class="muted asr-filter-note">Privileged-asset filters require the EAM Dashboard dataset.</span>';
            $("asrTierFilter").innerHTML = "";
            $("asrClassificationFilter").innerHTML = "";
        }
        $("asrSearch").value = asrState.search;
        var resources = asrFilteredResources();
        var groups = asrResourceGroups(resources);
        var familyCount = groups.reduce(function (count, product) { return count + product.families.length; }, 0);
        var treeHtml = groups.map(function (product, productIndex) {
            var productResources = product.families.reduce(function (items, family) { return items.concat(family.resources); }, []);
            var containsSelection = productResources.some(function (resource) { return resource.p === asrState.selectedPath; });
            var productExpanded = !!asrState.search.trim() || asrState.expandedProducts.has(product.key);
            var productId = "asr-product-" + productIndex;
            var familiesHtml = product.families.map(function (family, familyIndex) {
                var familyExpanded = !!asrState.search.trim() || asrState.expandedFamilies.has(family.key);
                var familyContainsSelection = family.resources.some(function (resource) { return resource.p === asrState.selectedPath; });
                var familyId = productId + "-family-" + familyIndex;
                var resourcesHtml = family.resources.map(function (resource) {
                    var description = resource.category || resource.type;
                    return '<button type="button" role="treeitem" aria-level="3" class="asr-resource' + (resource.p === asrState.selectedPath ? ' selected' : '') + '" data-asr-resource="' + esc(resource.p) + '"><span class="asr-resource-icon" aria-hidden="true">&#9671;</span><span class="asr-resource-copy"><strong>' + asrHighlight(resource.name) + '</strong><span>' + asrHighlight(description) + '</span></span><span class="asr-resource-status ' + asrResourceStatus(resource.p) + '">' + asrResourceStatus(resource.p) + '</span></button>';
                }).join("");
                return '<div class="asr-family' + (familyContainsSelection ? ' contains-selection' : '') + '"><button type="button" role="treeitem" aria-level="2" aria-expanded="' + familyExpanded + '" aria-controls="' + familyId + '" class="asr-folder-row asr-family-row" data-asr-family="' + esc(family.key) + '"><span class="asr-folder-chevron" aria-hidden="true">' + (familyExpanded ? "&#9662;" : "&#9656;") + '</span><span class="asr-folder-icon" aria-hidden="true">&#9638;</span><span class="asr-folder-name">' + esc(family.name) + '</span><span class="asr-folder-count">' + family.resources.length.toLocaleString() + '</span></button><div id="' + familyId + '" class="asr-folder-children" role="group"' + (familyExpanded ? "" : " hidden") + '>' + resourcesHtml + '</div></div>';
            }).join("");
            return '<div class="asr-folder asr-product ' + esc(product.meta.className) + (containsSelection ? ' contains-selection' : '') + '"><button type="button" role="treeitem" aria-level="1" aria-expanded="' + productExpanded + '" aria-controls="' + productId + '" class="asr-folder-row asr-product-row" data-asr-product="' + esc(product.key) + '"><span class="asr-folder-chevron" aria-hidden="true">' + (productExpanded ? "&#9662;" : "&#9656;") + '</span><span class="asr-product-icon" aria-hidden="true">' + product.meta.icon + '</span><span class="asr-folder-name">' + esc(product.meta.label) + '</span><span class="asr-folder-count">' + productResources.length.toLocaleString() + '</span></button><div id="' + productId + '" class="asr-folder-children" role="group"' + (productExpanded ? "" : " hidden") + '>' + familiesHtml + '</div></div>';
        }).join("");
        list.innerHTML = '<div class="asr-list-head"><span>' + resources.length.toLocaleString() + ' of ' + allResources.length.toLocaleString() + ' resources in ' + familyCount.toLocaleString() + ' families</span><span class="asr-tree-actions"><button type="button" title="Expand all resource families" aria-label="Expand all resource families" data-asr-tree-action="expand">+</button><button type="button" title="Collapse all resource families" aria-label="Collapse all resource families" data-asr-tree-action="collapse">&#8722;</button></span></div>' +
            (resources.length ? '<div class="asr-tree" role="tree">' + treeHtml + '</div>' : '<div class="muted asr-empty">No resources match the current filters.</div>');
        list.querySelectorAll("[data-asr-product]").forEach(function (button) {
            button.addEventListener("click", function () {
                var product = button.getAttribute("data-asr-product");
                if (asrState.expandedProducts.has(product)) asrState.expandedProducts.delete(product);
                else asrState.expandedProducts.add(product);
                renderAllSnapshotResources();
            });
        });
        list.querySelectorAll("[data-asr-family]").forEach(function (button) {
            button.addEventListener("click", function () {
                var family = button.getAttribute("data-asr-family");
                if (asrState.expandedFamilies.has(family)) asrState.expandedFamilies.delete(family);
                else asrState.expandedFamilies.add(family);
                renderAllSnapshotResources();
            });
        });
        list.querySelectorAll("[data-asr-resource]").forEach(function (button) {
            button.addEventListener("click", function () { asrState.selectedPath = button.getAttribute("data-asr-resource"); renderAllSnapshotResources(); });
        });
        list.querySelectorAll("[data-asr-tree-action]").forEach(function (button) {
            button.addEventListener("click", function () {
                var expand = button.getAttribute("data-asr-tree-action") === "expand";
                asrState.expandedProducts = expand ? new Set(groups.map(function (product) { return product.key; })) : new Set();
                asrState.expandedFamilies = expand ? new Set(groups.reduce(function (keys, product) { return keys.concat(product.families.map(function (family) { return family.key; })); }, [])) : new Set();
                renderAllSnapshotResources();
            });
        });
        var privilegedToggle = $("asrPrivilegedOnly");
        if (privilegedToggle) privilegedToggle.addEventListener("change", function () { asrState.privilegedOnly = this.checked; asrState.selectedPath = ""; renderAllSnapshotResources(); });
        var tierFilter = $("asrTier");
        if (tierFilter) tierFilter.addEventListener("change", function () { asrState.tierFilter = this.value; asrState.selectedPath = ""; renderAllSnapshotResources(); });
        var classificationFilter = $("asrClassification");
        if (classificationFilter) classificationFilter.addEventListener("change", function () { asrState.classificationFilter = this.value; asrState.selectedPath = ""; renderAllSnapshotResources(); });
        renderAsrDetail();
    }

    // =====================================================================================
    // Configuration Assets
    // =====================================================================================
    var paState = { snapshotIdx: -1, tierFilter: "", resourceType: "", search: "", includeAllTypes: false, deepResourcePath: "", expandTierSelection: false };

    function resourceDeepLink(snapshotIdx, resourcePath) {
        return "#resource=" + snapshotIdx + "|" + encodeURIComponent(resourcePath);
    }

    function configurationObjectDeepLink(snapshotIdx, resourcePath) {
        return "#config-object=" + snapshotIdx + "|" + encodeURIComponent(resourcePath);
    }

    function applyConfigurationObjectDeepLink() {
        var match = /^#config-object=(\d+)\|(.+)$/.exec(location.hash);
        if (!match) return false;
        var snapshotIdx = Number(match[1]);
        var resourcePath;
        try { resourcePath = decodeURIComponent(match[2]); } catch (_) { return false; }
        var snapshot = snapshots[snapshotIdx];
        var resource = snapshot && snapshotResourceByPath(snapshot).get(resourcePath);
        if (!resource || !snapshot.hasDetail) return false;
        paState.snapshotIdx = snapshotIdx;
        paState.resourceType = resource.type;
        paState.search = "";
        paState.tierFilter = "";
        paState.deepResourcePath = resourcePath;
        return true;
    }

    function applyResourceDeepLink() {
        var match = /^#resource=(\d+)\|(.+)$/.exec(location.hash);
        if (!match) return false;
        var snapshotIdx = Number(match[1]);
        var resourcePath;
        try { resourcePath = decodeURIComponent(match[2]); } catch (_) { return false; }
        var snapshot = snapshots[snapshotIdx];
        var resource = snapshot && snapshotResourceByPath(snapshot).get(resourcePath);
        if (!resource || !snapshot.hasDetail) {
            snapshotIdx = detailedSnapshotIdxs().reverse().filter(function (index) {
                return snapshots[index].resources.some(function (item) { return item.p === resourcePath; });
            })[0];
            snapshot = snapshotIdx == null ? null : snapshots[snapshotIdx];
            resource = snapshot && snapshotResourceByPath(snapshot).get(resourcePath);
        }
        if (!resource || !snapshot) return false;
        asrState.snapshotIdx = snapshotIdx;
        asrState.currentIdx = snapshotIdx;
        asrState.baselineIdx = snapshotIdx > 0 ? snapshotIdx - 1 : -1;
        asrState.type = "";
        asrState.category = "";
        asrState.changeMode = "all";
        asrState.search = "";
        asrState.privilegedOnly = false;
        asrState.tierFilter = "";
        asrState.classificationFilter = "";
        asrState.selectedPath = resourcePath;
        asrState.expandedProducts = new Set();
        asrState.expandedFamilies = new Set();
        renderAllSnapshotResources();
        return true;
    }

    function renderPrivilegedAssetsControls() {
        var sel = $("paSnapshot");
        var idxs = detailedSnapshotIdxs();
        var html = "";
        idxs.forEach(function (i) {
            html += '<option value="' + i + '"' + (i === paState.snapshotIdx ? " selected" : "") + ">" + esc(snapshotLabel(snapshots[i], i)) + "</option>";
        });
        sel.innerHTML = html;
    }

    var PA_TIER_COLORS = { ControlPlane: "#a4262c", ManagementPlane: "#c07807", UserAccess: "#0e700e" };
    var PA_TIER_LABELS = { ControlPlane: "Control Plane", ManagementPlane: "Management Plane", UserAccess: "User Access" };

    function privilegedResourcesForType(snapshot, resourceType, tierFilter, includeAll) {
        return snapshot.resources.map(function (r) {
            if (r.type !== resourceType) return null;
            var blob = blobContent(r.h);
            if (!blob || !blob.properties) return null;
            var tiers = {};
            var assetsByKey = {};
            extractIdentityRefs(r.type, blob.properties).forEach(function (entry) {
                var ref = entry.ref;
                (identityTiersFor(ref) || []).forEach(function (tier) {
                    if (tier && PA_TIER_LABELS[tier]) tiers[tier] = true;
                });
                var group = resolvedGroupTierIndex.get(String(ref).toUpperCase()) || resolvedGroupTierByNameIndex.get(String(ref).toUpperCase());
                var reason = (entry.field || "Identity reference") + (group ? ' \u00b7 via group "' + (group.displayName || ref) + '"' : "");
                classifiedAssetsForReference(ref).forEach(function (asset) {
                    if (!asset.tierName || !PA_TIER_LABELS[asset.tierName]) return;
                    var key = String(asset.objectId || asset.displayName).toUpperCase() + "|" + asset.tierName;
                    if (!assetsByKey[key]) { asset.reasons = []; assetsByKey[key] = asset; }
                    if (assetsByKey[key].reasons.indexOf(reason) === -1) assetsByKey[key].reasons.push(reason);
                });
            });
            if ((!includeAll && !Object.keys(tiers).length) || (tierFilter && !tiers[tierFilter])) return null;
            return {
                resource: r,
                name: blob.properties.DisplayName || r.name,
                tiers: Object.keys(tiers),
                assets: Object.keys(assetsByKey).map(function (key) { return assetsByKey[key]; }).sort(function (a, b) { return a.displayName.localeCompare(b.displayName); })
            };
        }).filter(function (r) { return r !== null; }).sort(function (a, b) { return a.name.localeCompare(b.name); });
    }

    function openSnapshotResourceDetails(resource, tiers, updateUrl) {
        if (!resource || !window.EntraOpsObjectInspector) return;
        var blob = blobContent(resource.h) || {};
        var properties = blob.properties || {};
        var reference = properties.Id || properties.id || resource.name;
        var canonicalReference = window.EntraOpsObjectInspector.canonicalReference(reference);
        var orderedTiers = (tiers || []).slice().sort(function (left, right) { return tierRank(left) - tierRank(right); });
        window.EntraOpsObjectInspector.open({
            title: properties.DisplayName || resource.name,
            reference: reference,
            urlReference: canonicalReference,
            // The app owns the URL: it pushes a #config-object= deep link below when asked to.
            // Letting the inspector also push #object= would create two history entries per click.
            updateUrl: false,
            tier: orderedTiers.length ? orderedTiers[0] : null,
            fields: [
                { label: "Resource type", value: resource.type },
                { label: "Category", value: resource.category },
                { label: "Snapshot resource path", value: resource.p },
                { label: "Access tiers", value: orderedTiers.length ? orderedTiers.map(function (tier) { return PA_TIER_LABELS[tier]; }).join(", ") : null }
            ],
            htmlSections: [{
                title: "Configuration properties",
                html: renderPropertyTree(null, false, properties, true, "added")
            }]
        });
        if (updateUrl) history.pushState(null, "", configurationObjectDeepLink(paState.snapshotIdx, resource.p));
    }

    function filteredPrivilegedResources(ignoreTierFilter, resourceType) {
        // resourceType defaults to the selected type; passing it explicitly lets callers probe
        // other types (typeMatchesSearch) without mutating and restoring global paState.
        if (resourceType === undefined) resourceType = paState.resourceType;
        var resources = privilegedResourcesForType(snapshots[paState.snapshotIdx], resourceType, ignoreTierFilter ? "" : paState.tierFilter, paState.includeAllTypes);
        var search = paState.search.trim().toLowerCase();
        if (search) {
            resources = resources.map(function (item) {
                var resourceMatches = [item.name, item.resource.name, item.resource.type, item.resource.category, item.resource.p].some(function (value) {
                    return String(value || "").toLowerCase().indexOf(search) !== -1;
                });
                var matchingAssets = item.assets.filter(function (asset) {
                    return [asset.displayName, asset.userPrincipalName, asset.objectId, asset.objectType].concat(asset.services || []).concat(asset.reasons || []).some(function (value) {
                        return String(value || "").toLowerCase().indexOf(search) !== -1;
                    });
                });
                if (!resourceMatches && !matchingAssets.length) return null;
                if (resourceMatches) return item;
                return Object.assign({}, item, { assets: matchingAssets });
            }).filter(Boolean);
        }
        return resources;
    }

    function typeMatchesSearch(type) {
        if (!paState.search.trim()) return true;
        return filteredPrivilegedResources(true, type).length > 0;
    }

    // Shared row pipeline: renderPrivilegedAssets and the paExport handler must display/export
    // the SAME rows (tier/search/include-all filtering) so the CSV can never drift from the table.
    function displayedPrivilegedRows(snapshot) {
        var rows = privilegedAssetsForSnapshot(snapshot);
        var withIdentities = rows.filter(function (r) { return r.totalWithIdentities > 0; });
        return (paState.includeAllTypes ? rows : withIdentities).filter(function (row) {
            return (!paState.tierFilter || row.tiers[paState.tierFilter].length > 0) && typeMatchesSearch(row.type);
        });
    }

    function assetTierCountsHtml(assets) {
        var counts = { ControlPlane: 0, ManagementPlane: 0, UserAccess: 0 };
        assets.forEach(function (asset) { if (counts[asset.tierName] !== undefined) counts[asset.tierName]++; });
        return ["ControlPlane", "ManagementPlane", "UserAccess"].map(function (tier) {
            if (!counts[tier]) return '<span class="pa-tier-count empty" title="No ' + esc(PA_TIER_LABELS[tier]) + ' assets">&ndash;</span>';
            return '<span class="pa-tier-count" style="background:' + PA_TIER_COLORS[tier] + ';" title="' + esc(PA_TIER_LABELS[tier]) + ' assets">' + counts[tier] + '</span>';
        }).join("");
    }

    function assetTreeHtml(item) {
        var assets = item.assets.filter(function (asset) { return !paState.tierFilter || asset.tierName === paState.tierFilter; });
        var expandSelection = paState.expandTierSelection && !!paState.tierFilter;
        var html = '<details class="pa-resource-tree"' + (expandSelection ? " open" : "") + '><summary><span class="pa-tree-chevron" aria-hidden="true"></span><span class="pa-tree-resource"><strong>' + esc(item.name) + '</strong><span>' + esc(item.resource.category || item.resource.type) + '</span></span><span class="pa-tree-count">' + assetTierCountsHtml(assets) + '</span></summary><div class="pa-tree-children">';
        html += '<div class="pa-tree-actions"><a href="index.html?view=privileged' + configurationObjectDeepLink(paState.snapshotIdx, item.resource.p) + '" data-pa-source-resource="' + esc(item.resource.p) + '">Open snapshot details</a><a href="index.html?view=resources' + resourceDeepLink(paState.snapshotIdx, item.resource.p) + '">Open in Snapshot Resources</a></div>';
        ["ControlPlane", "ManagementPlane", "UserAccess"].forEach(function (tier) {
            var tierAssets = assets.filter(function (asset) { return asset.tierName === tier; });
            if (!tierAssets.length) return;
            var expandTier = expandSelection && paState.tierFilter === tier;
            html += '<details class="pa-tree-tier"' + (expandTier ? " open" : "") + '><summary class="pa-tree-tier-label"><span class="pa-tree-tier-chevron" aria-hidden="true"></span><span class="pa-tree-tier-swatch" style="background:' + PA_TIER_COLORS[tier] + '"></span><strong>' + esc(PA_TIER_LABELS[tier]) + '</strong><small>' + tierAssets.length + ' asset' + (tierAssets.length === 1 ? "" : "s") + '</small></summary><div class="pa-tree-assets">';
            tierAssets.forEach(function (asset) {
                var label = asset.displayName || asset.userPrincipalName || asset.objectId;
                var href = asset.objectId ? '../EamDashboard/index.html#asset=' + encodeURIComponent(asset.objectId) : "";
                html += '<div class="pa-tree-asset"><span class="pa-tree-branch" aria-hidden="true"></span><div><strong>' + (href ? '<a href="' + href + '">' + esc(label) + '</a>' : esc(label)) + '</strong><span>' + esc([asset.objectType, asset.userPrincipalName].filter(Boolean).join(" · ") || "EntraOps classified asset") + '</span>' + (asset.reasons && asset.reasons.length ? '<small>' + esc(asset.reasons.join("; ")) + '</small>' : "") + '</div></div>';
            });
            html += "</div></details>";
        });
        if (!assets.length) html += '<div class="muted">No classified assets match the current access-tier filter.</div>';
        return html + "</div></details>";
    }

    function renderRelatedAssets() {
        var container = $("paRelatedAssetsBody");
        if (!container) return;
        if (!paState.resourceType) {
            container.innerHTML = '<div class="pa-related-empty"><strong>Select a resource type</strong><span>Its referencing snapshot objects and EntraOps-classified assets will appear here as an expandable tree.</span></div>';
            return;
        }
        var resources = filteredPrivilegedResources();
        var assetCount = 0;
        var tierTotals = { ControlPlane: 0, ManagementPlane: 0, UserAccess: 0 };
        resources.forEach(function (item) {
            item.assets.forEach(function (asset) {
                if (paState.tierFilter && asset.tierName !== paState.tierFilter) return;
                assetCount++;
                if (tierTotals[asset.tierName] !== undefined) tierTotals[asset.tierName]++;
            });
        });
        var tierStats = ["ControlPlane", "ManagementPlane", "UserAccess"].map(function (tier) {
            return '<span class="pa-related-tier"><span class="swatch" style="background:' + PA_TIER_COLORS[tier] + ';"></span>' + esc(PA_TIER_LABELS[tier]) + ' ' + tierTotals[tier] + '</span>';
        }).join("");
        var html = '<div class="pa-related-head"><div><span class="muted">Selected resource type</span><code>' + esc(paState.resourceType) + '</code></div><div class="pa-related-stats"><span>' + resources.length + ' resources</span><span>' + assetCount + ' asset references</span>' + tierStats + '</div><button class="btn small" type="button" data-pa-compare-type>Compare type history</button></div>';
        if (!resources.length) html += '<div class="pa-related-empty"><strong>No matching relationships</strong><span>Adjust the search or access-tier filter.</span></div>';
        else html += '<div class="pa-resource-tree-list">' + resources.map(assetTreeHtml).join("") + "</div>";
        container.innerHTML = html;
        wirePrivilegedAssetBrowser(container);
    }

    function renderPrivilegedAssets() {
        var el = $("privilegedAssetsBody");
        if (paState.snapshotIdx < 0) {
            el.innerHTML = '<div class="muted">No detailed snapshot available - regenerate the dataset with a higher <code>-MaxDetailedSnapshots</code>.</div>';
            renderRelatedAssets();
            return;
        }
        var displayedRows = displayedPrivilegedRows(snapshots[paState.snapshotIdx]);
        if (!displayedRows.length) {
            el.innerHTML = '<div class="muted">No captured resource in this snapshot references a user or group in a field this app knows how to resolve.</div>';
            renderRelatedAssets();
            return;
        }

        function tierChip(tierName, list) {
            if (!list.length) return '<span class="muted">–</span>';
            var color = PA_TIER_COLORS[tierName];
            var selected = paState.tierFilter === tierName;
            return '<button type="button" class="status-chip pa-tier-filter' + (selected ? " selected" : "") + '" style="background:' + color + ';color:#fff;" data-pa-detail="' + esc(tierName) + '" aria-pressed="' + selected + '" title="Filter by ' + esc(PA_TIER_LABELS[tierName]) + '">' + list.length + "</button>";
        }

        var html = '<div class="table-wrap"><table class="grid-table"><thead><tr>' +
            '<th class="no-sort">Resource type</th><th class="no-sort">With identity refs</th>' +
            '<th class="no-sort">Control Plane</th><th class="no-sort">Management Plane</th><th class="no-sort">User Access</th>' +
            "</tr></thead><tbody>";
        displayedRows.forEach(function (row, i) {
            var typeSelected = paState.resourceType === row.type;
            var typeAction = typeSelected ? "Show related assets" : "Open related assets";
            html += '<tr data-pa-row="' + i + '">' +
                '<td><button type="button" class="pa-type-button' + (typeSelected ? " selected" : "") + '" data-pa-type="' + esc(row.type) + '" aria-controls="paRelatedAssetsBody" aria-expanded="' + typeSelected + '" aria-label="' + typeAction + ' for ' + esc(row.type) + '" title="' + typeAction + '"><span class="pa-type-chevron" aria-hidden="true"></span><code>' + esc(row.type) + '</code></button></td>' +
                "<td>" + row.totalWithIdentities + " / " + row.totalWithContent + "</td>" +
                "<td>" + tierChip("ControlPlane", row.tiers.ControlPlane) + "</td>" +
                "<td>" + tierChip("ManagementPlane", row.tiers.ManagementPlane) + "</td>" +
                "<td>" + tierChip("UserAccess", row.tiers.UserAccess) + "</td>" +
                "</tr>";
        });
        html += "</tbody></table></div>";
        el.innerHTML = html;

        el.querySelectorAll("[data-pa-detail]").forEach(function (chipEl) {
            chipEl.addEventListener("click", function () {
                var tr = chipEl.closest("tr[data-pa-row]");
                var i = Number(tr.getAttribute("data-pa-row"));
                var tier = chipEl.getAttribute("data-pa-detail");
                var row = displayedRows[i];
                var sameSelection = paState.resourceType === row.type && paState.tierFilter === tier && paState.expandTierSelection;
                paState.resourceType = row.type;
                paState.tierFilter = sameSelection ? "" : tier;
                paState.expandTierSelection = !sameSelection;
                $("paTierFilter").value = paState.tierFilter;
                renderPrivilegedAssets();
                renderRelatedAssets();
                if (!sameSelection) $("secRelatedAssets").scrollIntoView({ behavior: "smooth", block: "start" });
            });
        });
        wirePrivilegedAssetBrowser(el);
        renderRelatedAssets();
    }

    function wirePrivilegedAssetBrowser(container) {
        container.querySelectorAll("[data-pa-type]").forEach(function (el) {
            el.addEventListener("click", function (ev) {
                ev.stopPropagation();
                paState.resourceType = el.getAttribute("data-pa-type");
                paState.expandTierSelection = false;
                renderPrivilegedAssets();
                renderRelatedAssets();
                var updatedTypeButton = document.querySelector('[data-pa-type="' + CSS.escape(paState.resourceType) + '"]');
                if (updatedTypeButton) updatedTypeButton.focus();
                $("secRelatedAssets").scrollIntoView({ behavior: "smooth", block: "start" });
            });
        });
        container.querySelectorAll("[data-pa-source-resource]").forEach(function (link) {
            link.addEventListener("click", function (event) {
                event.preventDefault();
                event.stopPropagation();
                var path = link.getAttribute("data-pa-source-resource");
                var resource = snapshotResourceByPath(snapshots[paState.snapshotIdx]).get(path);
                if (!resource) return;
                var privileged = relatedPrivilegedObjects(resource.h, resource.type);
                openSnapshotResourceDetails(resource, privileged ? Array.from(privileged.tierNames) : [], true);
            });
        });
        var compare = container.querySelector("[data-pa-compare-type]");
        if (compare) compare.addEventListener("click", function () {
            state.typeFilter = paState.resourceType;
            renderTypeFilter();
            history.pushState(null, "", location.pathname);
            applyConfigurationView();
            // Render the timeline only after #secTimeline is visible again - a hidden
            // container reports zero width and the chart would clamp to its minimum.
            renderTimeline();
            var adjacentSnapshot = paState.snapshotIdx > 0 ? paState.snapshotIdx - 1 : Math.min(snapshots.length - 1, paState.snapshotIdx + 1);
            $("cmpBaseline").value = String(Math.min(paState.snapshotIdx, adjacentSnapshot));
            $("cmpCurrent").value = String(Math.max(paState.snapshotIdx, adjacentSnapshot));
            $("cmpRun").click();
            $("secCompare").scrollIntoView({ behavior: "smooth", block: "start" });
        });

        if (paState.deepResourcePath) {
            var deepResources = privilegedResourcesForType(snapshots[paState.snapshotIdx], paState.resourceType, paState.tierFilter, paState.includeAllTypes);
            var deepItem = deepResources.filter(function (item) { return item.resource.p === paState.deepResourcePath; })[0];
            paState.deepResourcePath = "";
            if (deepItem) {
                openSnapshotResourceDetails(deepItem.resource, deepItem.tiers);
            }
        }
    }

    // =====================================================================================
    // Snapshot health banner
    // =====================================================================================
    // Surfaces DATA.snapshotHealth (compact manifest extract emitted by
    // New-EntraOpsTenantGovernanceConfigurationAnalyzerData) when the analyzed Tenant
    // Governance snapshot was partial or carries stale resource types. Degrades silently
    // for older datasets without the field.
    function renderSnapshotHealth() {
        if (typeof renderEntraOpsSnapshotHealth === "function") renderEntraOpsSnapshotHealth("caSnapshotHealth");
    }

    // =====================================================================================
    // Wiring + init
    // =====================================================================================
    function onReady(fn) {
        if (document.readyState !== "loading") fn();
        else document.addEventListener("DOMContentLoaded", fn);
    }

    onReady(function () {
        var navToggle = $("navToggle");
        var nav = $("nav");
        if (navToggle && nav) {
            navToggle.addEventListener("click", function () { nav.classList.toggle("open"); });
        }
        document.querySelectorAll(".nav-item.section-item").forEach(function (item) {
            item.addEventListener("click", function () {
                var target = document.getElementById(item.getAttribute("data-target"));
                if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
                if (nav) nav.classList.remove("open");
            });
            item.addEventListener("keydown", function (event) {
                if (event.key !== "Enter" && event.key !== " ") return;
                event.preventDefault();
                item.click();
            });
        });

        // Snapshot health is independent of the analyzer's data views. Render it before the
        // empty-state return so partial-capture diagnostics are never hidden with caContent.
        renderSnapshotHealth();

        if (!DATA || !snapshots.length) return; // empty state stays visible

        $("caEmptyState").classList.add("hidden");
        $("caContent").classList.remove("hidden");
        applyConfigurationView();

        renderStats();
        renderTypeFilter();
        renderTimeline();
        renderCompareSelects();
        var timelineResizeFrame = null;
        window.addEventListener("resize", function () {
            if (timelineResizeFrame) cancelAnimationFrame(timelineResizeFrame);
            timelineResizeFrame = requestAnimationFrame(renderTimeline);
        });

        setExplorerSnapshot(snapshots.length - 1, false);
        $("asrSnapshot").addEventListener("change", function () { setExplorerSnapshot(Number(this.value), true); });
        $("asrType").addEventListener("change", function () {
            asrState.type = this.value;
            state.typeFilter = this.value;
            asrState.selectedPath = "";
            asrState.expandedProducts = new Set();
            asrState.expandedFamilies = new Set();
            renderTypeFilter();
            renderTimeline();
            renderAllSnapshotResources();
        });
        $("asrCategory").addEventListener("change", function () { asrState.category = this.value; asrState.selectedPath = ""; renderAllSnapshotResources(); });
        $("asrChangeMode").addEventListener("change", function () {
            asrState.changeMode = this.value;
            asrState.selectedPath = "";
            asrState.expandedProducts = new Set();
            asrState.expandedFamilies = new Set();
            renderAllSnapshotResources();
        });
        var asrSearchTimer = null;
        $("asrSearch").addEventListener("input", function () {
            var value = this.value;
            clearTimeout(asrSearchTimer);
            asrSearchTimer = setTimeout(function () { asrState.search = value; asrState.selectedPath = ""; renderAllSnapshotResources(); }, 120);
        });
        $("asrClearFilters").addEventListener("click", function () {
            asrState.type = ""; asrState.category = ""; asrState.changeMode = "all"; asrState.search = "";
            asrState.privilegedOnly = false; asrState.tierFilter = ""; asrState.classificationFilter = "";
            asrState.selectedPath = ""; asrState.expandedProducts = new Set(); asrState.expandedFamilies = new Set();
            state.typeFilter = "";
            renderTypeFilter(); renderTimeline(); renderAllSnapshotResources();
        });
        $("asrList").addEventListener("keydown", function (event) {
            var focusable = Array.prototype.slice.call($("asrList").querySelectorAll("[data-asr-product], [data-asr-family], [data-asr-resource]")).filter(function (element) { return element.offsetParent !== null; });
            var index = focusable.indexOf(document.activeElement);
            if (index < 0) return;
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                focusable[Math.max(0, Math.min(focusable.length - 1, index + (event.key === "ArrowDown" ? 1 : -1)))].focus();
            } else if (event.key === "ArrowRight" && document.activeElement.hasAttribute("aria-expanded") && document.activeElement.getAttribute("aria-expanded") === "false") {
                event.preventDefault(); document.activeElement.click();
            } else if (event.key === "ArrowLeft" && document.activeElement.hasAttribute("aria-expanded") && document.activeElement.getAttribute("aria-expanded") === "true") {
                event.preventDefault(); document.activeElement.click();
            }
        });
        document.addEventListener("keydown", function (event) {
            var active = document.activeElement;
            if (event.key !== "/" || (active && /INPUT|SELECT|TEXTAREA/.test(active.tagName))) return;
            if ($("secAllSnapshotResources").hidden) return; // search box is not visible in this view
            event.preventDefault();
            $("asrSearch").focus();
        });

        var paDetailIdxs = detailedSnapshotIdxs();
        if (paDetailIdxs.length) paState.snapshotIdx = paDetailIdxs[paDetailIdxs.length - 1];
        applyResourceDeepLink();
        applyConfigurationObjectDeepLink();
        renderPrivilegedAssetsControls();
        renderPrivilegedAssets();
        $("paSnapshot").addEventListener("change", function () {
            paState.snapshotIdx = Number(this.value);
            paState.expandTierSelection = false;
            renderPrivilegedAssets();
        });
        $("paSearch").addEventListener("input", function () {
            paState.search = this.value;
            paState.expandTierSelection = false;
            renderPrivilegedAssets();
        });
        $("paTierFilter").addEventListener("change", function () {
            paState.tierFilter = this.value;
            paState.expandTierSelection = false;
            renderPrivilegedAssets();
        });
        $("paIncludeAllTypes").addEventListener("change", function () {
            paState.includeAllTypes = this.checked;
            paState.expandTierSelection = false;
            renderPrivilegedAssets();
        });

        if (state.selectedIdx > 0) {
            var chip = $("changesChip");
            chip.classList.remove("hidden");
            chip.textContent = snapshotLabel(snapshots[state.selectedIdx], state.selectedIdx) + " vs. " + snapshotLabel(snapshots[state.selectedIdx - 1], state.selectedIdx - 1);
            renderChangeList(snapshots[state.selectedIdx - 1], snapshots[state.selectedIdx], $("changesBody"));
        }

        $("fltResourceType").addEventListener("change", function () {
            state.typeFilter = this.value;
            asrState.type = this.value;
            asrState.selectedPath = "";
            asrState.expandedProducts = new Set();
            asrState.expandedFamilies = new Set();
            renderTimeline();
            renderAllSnapshotResources();
            if (state.selectedIdx > 0) {
                renderChangeList(snapshots[state.selectedIdx - 1], snapshots[state.selectedIdx], $("changesBody"));
            }
        });

        $("timelineView").addEventListener("change", function () {
            state.timelineView = this.value;
            renderTimeline();
        });

        $("cmpRun").addEventListener("click", function () {
            var b = Number($("cmpBaseline").value), c = Number($("cmpCurrent").value);
            if (b === c) {
                $("cmpResult").innerHTML = '<div class="muted">Pick two different snapshots to compare.</div>';
                return;
            }
            renderChangeList(snapshots[Math.min(b, c)], snapshots[Math.max(b, c)], $("cmpResult"));
        });

        $("timelineExport").addEventListener("click", function () {
            var aggregated = state.timelineView === "week" || state.timelineView === "month";
            var rows = timelineEntries().map(function (entry) {
                var snapshot = snapshots[entry.idx];
                if (aggregated) {
                    return { period: entry.periodLabel, firstCapture: fmtDate(snapshots[entry.startIdx].commitDate), lastCapture: fmtDate(snapshot.commitDate), snapshots: entry.captures, added: entry.added, modified: entry.modified, removed: entry.removed };
                }
                return { snapshot: snapshotLabel(snapshot, entry.idx), date: fmtDate(snapshot.commitDate), commit: snapshot.commitSha, subject: snapshot.subject || "", resources: snapshot.resources.length, added: entry.added, modified: entry.modified, removed: entry.removed };
            });
            EntraOpsReportUtils.exportRows("entraops-configuration-change-timeline", rows);
        });
        $("changesExport").addEventListener("click", function () {
            var index = state.selectedIdx;
            EntraOpsReportUtils.exportRows("entraops-configuration-snapshot-changes", index > 0 ? exportChangeRows(snapshots[index - 1], snapshots[index]) : []);
        });
        $("compareExport").addEventListener("click", function () {
            var baseline = Number($("cmpBaseline").value), current = Number($("cmpCurrent").value);
            EntraOpsReportUtils.exportRows("entraops-configuration-snapshot-compare", baseline === current ? [] : exportChangeRows(snapshots[Math.min(baseline, current)], snapshots[Math.max(baseline, current)]));
        });
        $("asrExport").addEventListener("click", function () {
            var rows = asrFilteredResources().map(function (resource) {
                var privileged = asrPrivilege(resource);
                return { snapshot: snapshotLabel(snapshots[asrState.snapshotIdx], asrState.snapshotIdx), state: asrResourceStatus(resource.p), resourceType: resource.type, category: resource.category || "", name: resource.name, path: resource.p, privilegedTiers: privileged ? Array.from(privileged.tierNames).join("; ") : "", classifications: privileged ? Array.from(privileged.services).join("; ") : "" };
            });
            EntraOpsReportUtils.exportRows("entraops-snapshot-resource-explorer", rows);
        });
        $("paExport").addEventListener("click", function () {
            var snapshot = snapshots[paState.snapshotIdx];
            var rows = [];
            if (snapshot) {
                // Same shared pipeline as renderPrivilegedAssets - exports exactly the displayed rows.
                rows = displayedPrivilegedRows(snapshot).map(function (row) {
                    return { snapshot: snapshotLabel(snapshot, paState.snapshotIdx), resourceType: row.type, resourcesWithIdentityReferences: row.totalWithIdentities, resourcesWithContent: row.totalWithContent, controlPlaneResources: row.tiers.ControlPlane.join("; "), managementPlaneResources: row.tiers.ManagementPlane.join("; "), userAccessResources: row.tiers.UserAccess.join("; ") };
                });
            }
            EntraOpsReportUtils.exportRows("entraops-privileged-assets", rows);
        });

        window.addEventListener("hashchange", function () {
            if (applyResourceDeepLink()) {
                applyConfigurationView();
                $("secAllSnapshotResources").scrollIntoView({ behavior: "smooth", block: "start" });
            } else if (applyConfigurationObjectDeepLink()) {
                applyConfigurationView();
                renderPrivilegedAssetsControls();
                renderPrivilegedAssets();
            }
        });
    });
})();
