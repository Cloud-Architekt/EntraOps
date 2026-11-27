/*
 * EntraOps Tier Breach Analyzer
 * Sankey view of privileged assignment paths and Enterprise Access Model
 * tier boundary violations, generated from EntraOps Privileged EAM data.
 *
 * Data contract: window.ENTRAOPS_TB_DATA = {
 *   generatedFrom: [..], tierLabels: {..}, objects: [..], paths: [..],
 *   scopeReasoningByScope: { "<scopeId>": [..] }   // shared per scope; older files inline
 *                                                  // paths[].scopeReasoning instead
 * } written by New-EntraOpsTierBreachAnalyzerData.
 */
(function () {
    "use strict";

    const DATA = window.ENTRAOPS_TB_DATA;
    if (DATA && typeof DATA.tenantName === "string" && DATA.tenantName.trim()) {
        document.getElementById("tenantName").textContent = DATA.tenantName.trim();
    }
    if (window.EOReview) {
        EOReview.init({ app: "TierBreachAnalyzer", appLabel: "Tier Breach Analyzer" });
    }
    if (!DATA || !Array.isArray(DATA.paths)) {
        document.addEventListener("DOMContentLoaded", function () {
            const app = document.getElementById("app");
            const box = document.createElement("div");
            box.className = "error-box";
            box.innerHTML =
                "<strong>No dataset found.</strong><br>" +
                "Generate <code>data/tier-breach-data.js</code> from your EntraOps Privileged EAM export first:" +
                "<br><br><code>Import-Module ./EntraOps; New-EntraOpsTierBreachAnalyzerData</code>" +
                "<br><br>then reload this page.";
            const head = app.querySelector(".page-head");
            if (head) head.after(box);
            else app.appendChild(box);
        });
        return;
    }

    // ---- Constants (Enterprise Access Model palette) ------------------------
    const TIER_COLORS = { 0: "#a4262c", 1: "#c07807", 2: "#0e700e" };
    const ROLE_COLOR = "#8a8886";
    const TIER_LABEL = {
        0: "Tier 0 - Control Plane",
        1: "Tier 1 - Management Plane",
        2: "Tier 2 - User Access",
    };
    const TIER_BADGE_CLASS = {
        0: "tier-controlplane",
        1: "tier-managementplane",
        2: "tier-useraccess",
    };

    const COLUMNS = {
        objectTier: {
            label: "Object tier",
            id: (p) => "ot" + p.objectTier,
            name: (p) => TIER_LABEL[p.objectTier],
            tier: (p) => p.objectTier,
            kind: "tier",
        },
        object: {
            label: "Object",
            id: (p) => "o|" + p.objectId,
            name: (p) => p.objectName,
            tier: (p) => p.objectTier,
            kind: "object",
            meta: (p) => (p.objectType === "user" ? "User" : "Service principal"),
        },
        role: {
            label: "Role",
            id: (p) => "r|" + p.system + "|" + p.role,
            name: (p) => p.role,
            tier: () => null,
            kind: "role",
            meta: (p) => p.system,
        },
        service: {
            label: "Service",
            id: (p) => "s|" + p.service,
            name: (p) => p.service,
            tier: (p) => p.serviceTier,
            kind: "service",
        },
        serviceTier: {
            label: "Service tier",
            id: (p) => "st" + p.serviceTier,
            name: (p) => TIER_LABEL[p.serviceTier],
            tier: (p) => p.serviceTier,
            kind: "tier",
        },
    };
    const COLUMN_ORDER = ["objectTier", "object", "role", "service", "serviceTier"];
    const DEFAULT_COLUMNS = ["objectTier", "role", "service"];

    // ---- State -------------------------------------------------------------
    const PAGE_STEP = 250;

    const state = {
        view: "tier0",
        columns: new Set(DEFAULT_COLUMNS),
        systems: new Set(),
        types: new Set(["user", "serviceprincipal"]),
        search: "",
        tableFilter: null, // { column, id, label } set when a Sankey node is clicked
        // Expanded detail rows, keyed by rowKey(). Held in state rather than in the DOM so an
        // expanded row survives a re-render (the table is rebuilt on every search keystroke).
        openRows: new Set(),
        // Rows whose scope reasoning list is filtered to Control Plane only, keyed by rowKey().
        // In state for the same reason as openRows: the table is rebuilt on every keystroke.
        scopeFilters: new Set(),
        // Number of breach rows rendered. Large tenants produce tens of thousands of paths and
        // every row carries a detail row, so the table is paged like the sibling reports.
        breachLimit: PAGE_STEP,
    };

    let currentBreaches = []; // last rendered breach rows (for CSV export)

    // Stable identity for a breach path. Deliberately the same composite the review-list deep link
    // uses (#sel=...), so open-row state, star ids and deep links all agree on what "a row" is.
    // A positional index cannot be used: it changes whenever a filter or the sort input changes.
    function rowKey(p) {
        return [p.objectId, p.role, p.service, p.scopeId || ""].join("||");
    }

    // Trailing-edge debounce. Search input and window resize both drive a full rebuild of the
    // table and the Sankey layout, which is far too expensive to run per keystroke or per resize tick.
    function debounce(fn, wait) {
        let timer = null;
        return function (...args) {
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => {
                timer = null;
                fn.apply(this, args);
            }, wait);
        };
    }

    // ---- Build control UI --------------------------------------------------
    const systems = Array.from(new Set(DATA.paths.map((p) => p.system))).sort();
    systems.forEach((s) => state.systems.add(s));

    buildLegend();
    buildColumnChecks();
    buildSystemChecks();
    buildTypeChecks();
    buildViewNav();

    // Debounced: every keystroke otherwise rebuilt the full table and re-ran the Sankey layout.
    // 180ms matches the sibling reports (AccessPathMap, ConfigurationAnalyzer).
    const renderDebounced = debounce(render, 180);
    document.getElementById("search").addEventListener("input", (e) => {
        state.search = e.target.value.trim().toLowerCase();
        renderDebounced();
    });

    document.getElementById("exportCsv").addEventListener("click", exportCsv);
    document.getElementById("clearFilter").addEventListener("click", () => {
        state.tableFilter = null;
        updateFilterTag();
        render();
    });

    document.getElementById("navToggle").addEventListener("click", () => {
        document.getElementById("nav").classList.toggle("open");
    });

    function buildViewNav() {
        document.querySelectorAll(".nav-item.view-item").forEach((el) => {
            const activate = () => {
                state.view = el.dataset.view;
                document
                    .querySelectorAll(".nav-item.view-item")
                    .forEach((n) => n.classList.toggle("active", n === el));
                document.getElementById("nav").classList.remove("open");
                render();
            };
            el.addEventListener("click", activate);
            el.addEventListener("keydown", (e) => {
                if (e.key !== "Enter" && e.key !== " ") return;
                e.preventDefault();
                activate();
            });
        });
    }

    function buildLegend() {
        const el = document.getElementById("legend");
        const items = [
            ["Tier 0 (Control Plane)", TIER_COLORS[0]],
            ["Tier 1 (Management Plane)", TIER_COLORS[1]],
            ["Tier 2 (User Access)", TIER_COLORS[2]],
            ["Role", ROLE_COLOR],
        ];
        el.innerHTML =
            '<span class="legend">' +
            items
                .map(
                    (i) =>
                        `<span class="item"><span class="swatch" style="background:${i[1]}"></span>${i[0]}</span>`
                )
                .join("") +
            "</span>";
    }

    function buildColumnChecks() {
        const el = document.getElementById("columnChecks");
        el.innerHTML = COLUMN_ORDER.map(
            (k) =>
                `<label><input type="checkbox" data-col="${esc(k)}" ${state.columns.has(k) ? "checked" : ""
                }/>${esc(COLUMNS[k].label)}</label>`
        ).join("");
        el.querySelectorAll("input").forEach((cb) =>
            cb.addEventListener("change", (e) => {
                const k = e.target.dataset.col;
                if (e.target.checked) state.columns.add(k);
                else state.columns.delete(k);
                render();
            })
        );
    }

    function buildSystemChecks() {
        const el = document.getElementById("systemChecks");
        el.innerHTML = systems
            .map(
                (s) =>
                    `<label><input type="checkbox" data-sys="${esc(s)}" checked/>${esc(s)}</label>`
            )
            .join("");
        el.querySelectorAll("input").forEach((cb) =>
            cb.addEventListener("change", (e) => {
                const s = e.target.dataset.sys;
                if (e.target.checked) state.systems.add(s);
                else state.systems.delete(s);
                render();
            })
        );
    }

    function buildTypeChecks() {
        const el = document.getElementById("typeChecks");
        const types = [
            ["user", "Users"],
            ["serviceprincipal", "Service principals"],
        ];
        el.innerHTML = types
            .map(
                (t) =>
                    `<label><input type="checkbox" data-type="${esc(t[0])}" checked/>${esc(t[1])}</label>`
            )
            .join("");
        el.querySelectorAll("input").forEach((cb) =>
            cb.addEventListener("change", (e) => {
                const t = e.target.dataset.type;
                if (e.target.checked) state.types.add(t);
                else state.types.delete(t);
                render();
            })
        );
    }

    // ---- Filtering ---------------------------------------------------------
    function baseFilteredPaths() {
        // System / type / search filters, without the view (breach) filter.
        const q = state.search;
        return DATA.paths.filter((p) => {
            if (!state.types.has(p.objectType)) return false;
            if (!state.systems.has(p.system)) return false;
            if (q) {
                const hay = (
                    p.objectName +
                    " " +
                    p.role +
                    " " +
                    p.service
                ).toLowerCase();
                if (!hay.includes(q)) return false;
            }
            return true;
        });
    }

    function filteredPaths() {
        const base = baseFilteredPaths();
        if (state.view === "tier0") return base.filter((p) => p.tier0Breach);
        if (state.view === "breach") return base.filter((p) => p.breach);
        return base;
    }

    // ---- Build Sankey graph ------------------------------------------------
    function buildGraph(paths) {
        const activeCols = COLUMN_ORDER.filter((k) => state.columns.has(k));
        const nodeMap = new Map();
        const linkMap = new Map();

        function ensureNode(colKey, p) {
            const col = COLUMNS[colKey];
            const id = col.id(p);
            if (!nodeMap.has(id)) {
                nodeMap.set(id, {
                    id,
                    name: col.name(p),
                    tier: col.tier(p),
                    kind: col.kind,
                    meta: col.meta ? col.meta(p) : null,
                    column: colKey,
                    value: 0,
                });
            }
            return id;
        }

        paths.forEach((p) => {
            const ids = activeCols.map((c) => ensureNode(c, p));
            for (let i = 0; i < ids.length - 1; i++) {
                const sId = ids[i];
                const tId = ids[i + 1];
                const key = sId + "→" + tId;
                let link = linkMap.get(key);
                if (!link) {
                    link = {
                        source: sId,
                        target: tId,
                        value: 0,
                        breach: false,
                        tier0Breach: false,
                    };
                    linkMap.set(key, link);
                }
                link.value += 1;
                if (p.breach) link.breach = true;
                if (p.tier0Breach) link.tier0Breach = true;
            }
        });

        const nodes = Array.from(nodeMap.values());
        const index = new Map(nodes.map((n, i) => [n.id, i]));
        const links = Array.from(linkMap.values()).map((l) => ({
            source: index.get(l.source),
            target: index.get(l.target),
            value: l.value,
            breach: l.breach,
            tier0Breach: l.tier0Breach,
        }));
        return { nodes, links };
    }

    // ---- Rendering ---------------------------------------------------------
    const svg = d3.select("#sankey");
    const tooltip = d3.select("#tooltip");

    function nodeColor(n) {
        if (n.kind === "role") return ROLE_COLOR;
        if (n.tier === 0 || n.tier === 1 || n.tier === 2) return TIER_COLORS[n.tier];
        return "#a19f9d";
    }

    function render() {
        // render() is the "inputs changed" entry point (search, view, column/system/type filters), so
        // the result set differs and paging restarts at the first page. The pager's own Show more/all
        // buttons deliberately call renderBreachTable() directly to keep the enlarged window.
        state.breachLimit = PAGE_STEP;

        const base = baseFilteredPaths();
        updateViewCounts(base);

        const paths = filteredPaths();

        // A Sankey-node table filter only makes sense while that node exists in the
        // current diagram (its column is active and at least one filtered path still
        // maps to it) - otherwise it silently pins the table to "0 breach path(s)".
        if (state.tableFilter) {
            const f = state.tableFilter;
            const nodeExists =
                state.columns.has(f.column) &&
                paths.some((p) => COLUMNS[f.column].id(p) === f.id);
            if (!nodeExists) {
                state.tableFilter = null;
                updateFilterTag();
            }
        }

        renderStats(paths);
        renderBreachTable(paths);
        renderDiagram(paths);
    }

    // Diagram-only redraw. Split out of render() so a window resize - which changes the available
    // width and therefore the Sankey layout, but not the data - does not also rebuild the whole
    // breach table. The last path set is retained so the resize handler has something to lay out.
    let lastDiagramPaths = [];
    function renderDiagram(paths) {
        if (paths) lastDiagramPaths = paths;
        const current = lastDiagramPaths;

        const empty = document.getElementById("empty");
        if (current.length === 0 || state.columns.size < 2) {
            svg.selectAll("*").remove();
            svg.attr("height", 0);
            empty.classList.remove("hidden");
            empty.textContent =
                state.columns.size < 2
                    ? "Select at least two columns to draw a flow."
                    : "No data matches the current filters.";
            return;
        }
        empty.classList.add("hidden");

        const graph = buildGraph(current);
        drawSankey(graph);
    }

    function updateViewCounts(base) {
        const set = (id, n) => {
            const el = document.getElementById(id);
            if (el) el.textContent = n.toLocaleString();
        };
        set("cnt-tier0", base.filter((p) => p.tier0Breach).length);
        set("cnt-breach", base.filter((p) => p.breach).length);
        set("cnt-all", base.length);
    }

    function drawSankey(graph) {
        const nodeCount = graph.nodes.length;
        const width = Math.max(960, document.querySelector(".diagram-wrap").clientWidth - 48);
        const rowH = 22;
        const height = Math.max(420, nodeCount * rowH);

        svg.attr("width", width).attr("height", height);
        svg.selectAll("*").remove();

        const sankey = d3
            .sankey()
            .nodeWidth(16)
            .nodePadding(10)
            .extent([
                [8, 8],
                [width - 8, height - 8],
            ]);

        let layout;
        try {
            layout = sankey({
                nodes: graph.nodes.map((d) => Object.assign({}, d)),
                links: graph.links.map((d) => Object.assign({}, d)),
            });
        } catch (e) {
            document.getElementById("empty").classList.remove("hidden");
            document.getElementById("empty").textContent =
                "Unable to lay out graph (possible cycle). Try different columns.";
            return;
        }

        const { nodes, links } = layout;

        // Links
        const linkSel = svg
            .append("g")
            .attr("class", "links")
            .selectAll("path")
            .data(links)
            .join("path")
            .attr("class", "link")
            .attr("d", d3.sankeyLinkHorizontal())
            .attr("stroke", (d) =>
                d.tier0Breach ? TIER_COLORS[0] : d.breach ? TIER_COLORS[1] : "#c8c6c4"
            )
            .attr("stroke-opacity", (d) => (d.tier0Breach ? 0.5 : d.breach ? 0.4 : 0.35))
            .attr("stroke-width", (d) => Math.max(1, d.width))
            .on("mousemove", (ev, d) =>
                showTip(
                    ev,
                    `<b>${esc(d.source.name)}</b> → <b>${esc(d.target.name)}</b><br/>${d.value} assignment path(s)` +
                    (d.tier0Breach
                        ? "<br/><span style='color:#a4262c;font-weight:600'>Tier 0 breach</span>"
                        : "")
                )
            )
            .on("mouseleave", hideTip);

        // Nodes
        const nodeSel = svg
            .append("g")
            .attr("class", "nodes")
            .selectAll("g")
            .data(nodes)
            .join("g")
            .attr("class", "node");

        nodeSel
            .append("rect")
            .attr("x", (d) => d.x0)
            .attr("y", (d) => d.y0)
            .attr("width", (d) => d.x1 - d.x0)
            .attr("height", (d) => Math.max(2, d.y1 - d.y0))
            .attr("fill", (d) => nodeColor(d))
            .attr("rx", 2)
            .on("mousemove", (ev, d) =>
                showTip(
                    ev,
                    `<b>${esc(d.name)}</b>${d.meta ? " · " + esc(d.meta) : ""}<br/>` +
                    (d.tier !== null ? TIER_LABEL[d.tier] + "<br/>" : "") +
                    `${d.value} assignment path(s)`
                )
            )
            .on("mouseleave", hideTip)
            .on("click", (ev, d) => {
                ev.stopPropagation();
                highlight(d, nodeSel, linkSel);
                setTableFilterFromNode(d);
            });

        nodeSel
            .append("text")
            .attr("x", (d) => (d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6))
            .attr("y", (d) => (d.y0 + d.y1) / 2)
            .attr("dy", "0.35em")
            .attr("text-anchor", (d) => (d.x0 < width / 2 ? "start" : "end"))
            .text((d) => truncate(d.name, 38))
            .filter((d) => d.y1 - d.y0 < 9)
            .remove();
    }

    function highlight(node, nodeSel, linkSel) {
        const connected = new Set([node.index]);
        const visit = (n, dir) => {
            const ls = dir === "down" ? n.sourceLinks : n.targetLinks;
            ls.forEach((l) => {
                const next = dir === "down" ? l.target : l.source;
                if (!connected.has(next.index)) {
                    connected.add(next.index);
                    visit(next, dir);
                }
            });
        };
        visit(node, "down");
        visit(node, "up");

        nodeSel.classed("dim", (d) => !connected.has(d.index));
        linkSel.classed(
            "dim",
            (d) => !(connected.has(d.source.index) && connected.has(d.target.index))
        );
    }

    // Clear highlight on background click
    svg.on("click", function (ev) {
        if (ev.target.tagName === "svg") {
            svg.selectAll(".node").classed("dim", false);
            svg.selectAll(".link").classed("dim", false);
        }
    });

    // ---- Stats -------------------------------------------------------------
    function renderStats(paths) {
        const objects = new Set(paths.map((p) => p.objectId));
        const roles = new Set(paths.map((p) => p.system + "|" + p.role));
        const breaches = paths.filter((p) => p.breach);
        const tier0 = paths.filter((p) => p.tier0Breach);
        const tier0Roles = new Set(tier0.map((p) => p.system + "|" + p.role));
        const tier0Services = new Set(tier0.map((p) => p.service));

        const stats = [
            { num: objects.size, lbl: "Objects" },
            { num: roles.size, lbl: "Roles" },
            { num: paths.length, lbl: "Assignment paths" },
            { num: breaches.length, lbl: "Tier breaches", danger: true },
            { num: tier0.length, lbl: "Tier 0 breaches", danger: true },
            { num: tier0Roles.size, lbl: "Roles reaching Tier 0", danger: true },
            { num: tier0Services.size, lbl: "Tier 0 services", danger: true },
        ];
        document.getElementById("stats").innerHTML = stats
            .map(
                (s) =>
                    `<div class="stat"><span class="stat-accent" style="background:${s.danger ? "var(--tier-control)" : "var(--brand)"
                    }"></span><div class="stat-label">${s.lbl}</div><div class="stat-value"${s.danger ? ' style="color:var(--tier-control)"' : ""
                    }>${s.num.toLocaleString()}</div></div>`
            )
            .join("");
    }

    // ---- Breach table ------------------------------------------------------
    function renderBreachTable(paths) {
        let breaches = paths.filter((p) => p.breach);

        // Apply the node-click filter (paths passing through the selected node).
        if (state.tableFilter) {
            const f = state.tableFilter;
            breaches = breaches.filter((p) => COLUMNS[f.column].id(p) === f.id);
        }

        // Show tier0 first, then by tier delta, then object name.
        breaches.sort(
            (a, b) =>
                Number(b.tier0Breach) - Number(a.tier0Breach) ||
                b.objectTier - b.serviceTier - (a.objectTier - a.serviceTier) ||
                a.objectName.localeCompare(b.objectName)
        );

        currentBreaches = breaches;

        // Drop open-row state for rows that are no longer in the result set, so the set cannot grow
        // without bound as the operator filters around.
        if (state.openRows.size || state.scopeFilters.size) {
            const visible = new Set(breaches.map(rowKey));
            state.openRows.forEach((key) => {
                if (!visible.has(key)) state.openRows.delete(key);
            });
            state.scopeFilters.forEach((key) => {
                if (!visible.has(key)) state.scopeFilters.delete(key);
            });
        }

        if (state.breachLimit < PAGE_STEP) state.breachLimit = PAGE_STEP;
        const shown = breaches.slice(0, state.breachLimit);

        document.getElementById("breachCount").textContent =
            breaches.length + " breach path(s)";

        const tbody = document.querySelector("#breachTable tbody");
        // One localStorage read per render instead of one per row (see EOReview.idsSet).
        const reviewIds = window.EOReview ? EOReview.idsSet() : new Set();
        tbody.innerHTML = shown.map((p, i) => summaryRow(p, i, reviewIds) + detailRow(p, i)).join("");

        renderBreachPager(breaches.length);
    }

    // Row expand/collapse and review stars are handled by two delegated listeners bound once at
    // startup, instead of one listener per row per render. At 10k breach paths the previous approach
    // attached ~20k listeners on every keystroke.
    function bindBreachTableEvents() {
        const tbody = document.querySelector("#breachTable tbody");

        // "Control Plane only" toggles inside an expanded detail row.
        tbody.addEventListener("change", (e) => {
            const toggle = e.target.closest("[data-scope-filter]");
            if (!toggle) return;
            const key = toggle.getAttribute("data-scope-filter");
            if (toggle.checked) state.scopeFilters.add(key);
            else state.scopeFilters.delete(key);
            const host = tbody.querySelector(`[data-scope-host="${CSS.escape(key)}"]`);
            if (host) host.classList.toggle("scope-reasoning-filtered", toggle.checked);
        });

        tbody.addEventListener("click", (e) => {
            // The filter checkbox lives inside the detail row; clicking it must not bubble up and
            // collapse the row (the row toggle is bound on the same tbody).
            if (e.target.closest("[data-scope-filter]") || e.target.closest("label.scope-filter-toggle")) {
                e.stopPropagation();
                return;
            }

            // Star first: it sits inside the row, and toggling a star must not expand the row.
            const star = e.target.closest("[data-star]");
            if (star) {
                e.stopPropagation();
                const p = currentBreaches[Number(star.dataset.star)];
                if (!p) return;
                const on = EOReview.toggle({
                    id: reviewIdFor(p),
                    kind: "Role",
                    system: p.system,
                    name: p.role,
                    scope: p.scopeName || p.scopeId || "",
                    tier: TIER_NAME[p.serviceTier] || "Unclassified",
                    hash: "#sel=" + encodeURIComponent(rowKey(p)),
                });
                EOReview.updateStar(star, on);
                return;
            }

            const tr = e.target.closest("tr.breach-row");
            if (!tr) return;
            const key = tr.dataset.key;
            const detail = tbody.querySelector(`tr.detail-row[data-row="${tr.dataset.row}"]`);
            const isOpen = tr.classList.toggle("open");
            tr.setAttribute("aria-expanded", isOpen ? "true" : "false");
            if (detail) detail.classList.toggle("hidden", !isOpen);
            if (isOpen) state.openRows.add(key);
            else state.openRows.delete(key);
        });

        // Keyboard support for the expandable rows (role="button" + tabindex="0"):
        // Enter/Space toggles the row like a click.
        tbody.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" && e.key !== " ") return;
            const tr = e.target.closest ? e.target.closest("tr.breach-row") : null;
            if (!tr || e.target.closest("[data-star],[data-scope-filter],a,button,input,label")) return;
            e.preventDefault();
            tr.click();
        });
    }

    function renderBreachPager(total) {
        const host = document.getElementById("breachPager");
        if (!host) return;
        if (total <= state.breachLimit) {
            host.classList.add("hidden");
            host.innerHTML = "";
            return;
        }
        host.classList.remove("hidden");
        host.innerHTML =
            `<span>Showing ${Math.min(state.breachLimit, total).toLocaleString()} of ${total.toLocaleString()} breach path(s)</span>` +
            `<button class="btn small" data-more>Show ${Math.min(PAGE_STEP, total - state.breachLimit).toLocaleString()} more</button>` +
            `<button class="btn small" data-all>Show all</button>`;
        host.querySelector("[data-more]").addEventListener("click", () => {
            state.breachLimit += PAGE_STEP;
            renderBreachTable(filteredPaths());
        });
        host.querySelector("[data-all]").addEventListener("click", () => {
            state.breachLimit = total;
            renderBreachTable(filteredPaths());
        });
    }

    function summaryRow(p, i, reviewIds) {
        const assign =
            (p.assignmentType
                ? `<span class="chip ${/transitive/i.test(p.assignmentType) ? "docdiff" : ""
                }">${esc(p.assignmentType)}</span> `
                : "") +
            (p.pimManaged ? `<span class="chip warn">PIM</span>` : "");
        const starId = reviewIdFor(p);
        const star = window.EOReview
            ? EOReview.starHtml(starId, undefined, reviewIds.has(starId)).replace("<button ", `<button data-eo-id="${esc(starId)}" data-star="${i}" `)
            : "";
        const key = rowKey(p);
        const isOpen = state.openRows.has(key);
        return (
            `<tr class="breach-row${isOpen ? " open" : ""}" data-row="${i}" data-key="${esc(key)}" role="button" tabindex="0" aria-expanded="${isOpen ? "true" : "false"}">` +
            `<td class="caret-col"><span class="caret">&#9654;</span></td>` +
            `<td class="cell-strong">${esc(p.objectName)}</td>` +
            `<td>${p.objectType === "user" ? "User" : "Service principal"}</td>` +
            `<td>${tierBadge(p.objectTier)}</td>` +
            `<td>${esc(p.system)}</td>` +
            `<td>${esc(p.role)}</td>` +
            `<td>${esc(p.service)}</td>` +
            `<td>${tierBadge(p.serviceTier)}</td>` +
            `<td>${esc(p.scopeName || "—")}${scopeReasoningBadge(pathScopeReasoning(p))}</td>` +
            `<td class="nowrap">${assign || "—"}</td>` +
            `<td>${star}</td>` +
            `</tr>`
        );
    }

    function detailRow(p, i) {
        const fields = [
            ["Why it is a breach", `Tier ${p.objectTier} object reaches a Tier ${p.serviceTier} service`],
            ["Object id", `<code>${esc(p.objectId)}</code>`],
            ["Role type", esc(p.roleType || "—")],
            ["Role is privileged", p.roleIsPrivileged ? "Yes" : "No"],
            ["Assignment id", `<code>${esc(p.assignmentId || "—")}</code>`],
            ["Assignment type", esc(p.assignmentType || "—")],
            ["Assignment sub-type", esc(p.assignmentSubType || "—")],
            ["Scope name", esc(p.scopeName || "—")],
            ["Scope id", `<code>${esc(p.scopeId || "—")}</code>`],
            ["PIM managed", p.pimManaged ? "Yes" : "No"],
            ["PIM assignment type", esc(p.pimAssignmentType || "—")],
            ["Inherited via (transitive)", esc(p.transitiveBy || "— (direct)")],
            ["Service classified by", esc(p.taggedBy || "—")],
            ["Classified in system", esc(p.taggedByRoleSystem || "—")],
        ];
        const grid = fields
            .map(
                (f) =>
                    `<div class="field"><span class="k">${f[0]}</span><span class="v">${f[1]}</span></div>`
            )
            .join("");
        const reasoning = scopeReasoningHtml(pathScopeReasoning(p), rowKey(p));
        // Restore the expanded state recorded in state.openRows: the table is rebuilt on every
        // keystroke, so without this an open row would collapse while the operator is typing.
        const isOpen = state.openRows.has(rowKey(p));
        return (
            `<tr class="detail-row${isOpen ? "" : " hidden"}" data-row="${i}">` +
            `<td colspan="11"><div class="detail-grid">${grid}</div>${reasoning}</td>` +
            `</tr>`
        );
    }

    // ---- Azure Tier0/Tier1 resource scope reasoning (ScopeReasoning_Azure.json) --
    // Explains why the assignment's scope id (and every ARM path above it) is
    // treated as Tier0/Tier1 resource scope: a privileged resource at/below that
    // scope (for example one hosting a system-assigned managed identity) caused the
    // whole ARM hierarchy above it to be included. Links jump to the EAM Dashboard
    // (sibling static-web app) asset view in a new tab.
    // Resolves a path's scope reasoning: newer data files share the reasoning per scopeId in
    // DATA.scopeReasoningByScope (it was ~100x duplicated inline before); older files still
    // carry an inline scopeReasoning array, which takes precedence as the fallback contract.
    function pathScopeReasoning(p) {
        if (p.scopeReasoning && p.scopeReasoning.length) return p.scopeReasoning;
        if (DATA.scopeReasoningByScope && p.scopeId) return DATA.scopeReasoningByScope[p.scopeId] || [];
        return [];
    }

    function scopeReasoningBadge(scopeReasoning) {
        if (!scopeReasoning || !scopeReasoning.length) return "";
        // Summarize the most privileged entry, matching the order the expanded list is rendered in,
        // so the tooltip and the detail row agree on which resource drove the scope.
        const driver = scopeReasoning.reduce((best, s) => (scopeTierRank(s.eamTier) < scopeTierRank(best.eamTier) ? s : best), scopeReasoning[0]);
        const more = scopeReasoning.length > 1 ? ` (+${scopeReasoning.length - 1} more)` : "";
        const title = `Why Tier0/Tier1 resource scope: ${driver.reason || ""}${more}`;
        return ` <span class="chip" title="${esc(title)}">&#9432; why?</span>`;
    }

    // Tier rank for scope reasoning entries. scopeReasoning[].eamTier is a tier *name* string, while
    // this app's own tierBadge() takes a numeric tier - hence a separate ordering table here.
    const SCOPE_TIER_RANK = { ControlPlane: 0, ManagementPlane: 1, WorkloadPlane: 2, UserAccess: 3, Unclassified: 4 };

    function scopeTierRank(tierName) {
        const rank = SCOPE_TIER_RANK[tierName];
        return rank === undefined ? SCOPE_TIER_RANK.Unclassified : rank;
    }

    function sortedScopeReasoning(scopeReasoning) {
        // Most privileged first: the entry that actually drove the Tier0/Tier1 scope should be read
        // first. Copy before sorting so the underlying path object is not reordered.
        return (scopeReasoning || []).slice().sort(
            (a, b) =>
                scopeTierRank(a.eamTier) - scopeTierRank(b.eamTier) ||
                String(a.resourceName || a.resourceId || "").localeCompare(String(b.resourceName || b.resourceId || ""))
        );
    }

    // One-line answer to "what did the scope actually do here", so the detail row does not have to be
    // read entry by entry. Every field below is optional: older tier-breach-data.js files carry only
    // resourceName/resourceId/eamTier/resultingScope/reason/managedIdentityObjectId, so the summary
    // degrades to tier + driver + reason rather than breaking.
    function scopeReasoningSummary(ordered) {
        if (!ordered.length) return "";
        const driver = ordered[0];
        const parts = [];

        const relationCounts = new Map();
        ordered.forEach((s) => {
            if (!s.scopeRelation) return;
            relationCounts.set(s.scopeRelation, (relationCounts.get(s.scopeRelation) || 0) + 1);
        });
        if (relationCounts.size) {
            parts.push(
                Array.from(relationCounts.entries())
                    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
                    .map(([relation, count]) => `${count.toLocaleString()} ${relation.toLowerCase()}`)
                    .join(", ")
            );
        }

        const driverName = driver.resourceName || driver.resourceId || "";
        if (driverName) {
            parts.push(
                `driven by <strong>${esc(driverName)}</strong>` +
                (driver.source ? ` via ${esc(driver.source)}` : "")
            );
        }

        const tierText = esc(driver.eamTier || "Unclassified");
        const countText = `${ordered.length.toLocaleString()} scope reason(s)`;
        const detail = parts.length ? `: ${parts.join(" &mdash; ")}` : "";
        const reason = driver.reason ? `<br/><span class="muted">${esc(driver.reason)}</span>` : "";

        return (
            `<div class="field scope-summary" style="grid-column:1/-1;">` +
            `<span class="k">Scope impact</span>` +
            `<span class="v"><span class="chip">${tierText}</span> ${countText}${detail}${reason}</span>` +
            `</div>`
        );
    }

    // "Control Plane only" toggle. Flips a class on the container rather than re-rendering, and the
    // checked state is held in state.scopeFilters so it survives the table rebuild on every keystroke.
    function scopeReasoningFilterHtml(ordered, key) {
        if (ordered.length < 2) return "";
        const controlPlaneCount = ordered.filter((s) => (s.eamTier || "") === "ControlPlane").length;
        if (!controlPlaneCount || controlPlaneCount === ordered.length) return "";
        const checked = state.scopeFilters.has(key) ? " checked" : "";
        return (
            `<div class="field" style="grid-column:1/-1;">` +
            `<span class="k">Filter</span>` +
            `<span class="v"><label class="chip scope-filter-toggle">` +
            `<input type="checkbox" data-scope-filter="${esc(key)}"${checked}/> Control Plane only</label> ` +
            `<span class="muted">${controlPlaneCount.toLocaleString()} of ${ordered.length.toLocaleString()} are Control Plane</span></span>` +
            `</div>`
        );
    }

    function scopeReasoningHtml(scopeReasoning, key) {
        if (!scopeReasoning || !scopeReasoning.length) return "";
        const ordered = sortedScopeReasoning(scopeReasoning);
        const items = ordered
            .map((s) => {
                const link = s.managedIdentityObjectId
                    ? ` &mdash; <a href="../EamDashboard/index.html#asset=${encodeURIComponent(s.managedIdentityObjectId)}" target="_blank" rel="noopener">View privileged asset &#8599;</a>`
                    : "";
                const relation = s.scopeRelation ? ` <span class="chip">${esc(s.scopeRelation)}</span>` : "";
                return (
                    `<div class="field scope-reason-entry" data-tier="${esc(s.eamTier || "Unclassified")}" style="grid-column:1/-1;">` +
                    `<span class="k">${esc(s.resourceName || s.resourceId || "")} (${esc(s.eamTier || "Unclassified")})</span>` +
                    `<span class="v">${esc(s.reason || "")}${relation}${link}</span>` +
                    `</div>`
                );
            })
            .join("");
        const filtered = state.scopeFilters.has(key) ? " scope-reasoning-filtered" : "";
        return (
            `<div class="detail-grid${filtered}" data-scope-host="${esc(key)}">` +
            `<div class="field" style="grid-column:1/-1;"><span class="k">Why Tier0/Tier1 resource scope</span></div>` +
            scopeReasoningSummary(ordered) +
            scopeReasoningFilterHtml(ordered, key) +
            items +
            `</div>`
        );
    }

    function tierBadge(t) {
        // Missing/unknown tiers render as "Unclassified" (like the EAM Dashboard),
        // never as "Tier undefined".
        const known = TIER_BADGE_CLASS[t] !== undefined;
        const cls = known ? TIER_BADGE_CLASS[t] : "tier-unclassified";
        return `<span class="tier-badge ${cls}"><span class="tier-dot"></span>${known ? "Tier " + t : "Unclassified"}</span>`;
    }

    const TIER_NAME = { 0: "ControlPlane", 1: "ManagementPlane", 2: "UserAccess" };

    function reviewIdFor(p) {
        return window.EOReview
            ? EOReview.makeId("role", p.system, p.role, p.scopeId || p.scopeName || "")
            : "";
    }

    // ---- Deep links (#sel=... jumps back to a starred breach row) -----------
    // #sel=<objectId>||<role>||<service>||<scopeId>[||<pathId>] or #path=<pathId>: a pathId identifies one breach
    // path, also when two role assignments share object, role, service and scope (the tuple then picks the first).
    function applyDeepLink() {
        const hash = location.hash || "";
        const pathMatch = hash.match(/^#path=(.+)$/);
        const m = pathMatch || hash.match(/^#sel=(.+)$/);
        if (!m) return;
        let decoded;
        try { decoded = decodeURIComponent(m[1]); } catch (_) { return; }
        const [objectId, role, service, scopeId, linkPathId] = pathMatch ? ["", "", "", "", decoded] : decoded.split("||");
        const pathId = String(linkPathId || "").toLowerCase();
        // The breach table lists breach paths of the current view; "breach" shows them all.
        if (state.view !== "breach" && state.view !== "all") {
            state.view = "breach";
            document.querySelectorAll(".nav-item.view-item").forEach((n) =>
                n.classList.toggle("active", n.dataset.view === "breach")
            );
            render();
        }
        const matchesLink = (p) => pathId
            ? String(p.pathId || "").toLowerCase() === pathId
            : p.objectId === objectId &&
                p.role === role &&
                p.service === service &&
                (p.scopeId || "") === (scopeId || "");
        let idx = currentBreaches.findIndex(matchesLink);
        // A breach path hidden by the search, the system and type filters or a Sankey node filter: clear them.
        if (idx === -1 && DATA.paths.some((p) => p.breach && matchesLink(p))) {
            clearFiltersForDeepLink();
            idx = currentBreaches.findIndex(matchesLink);
        }
        if (idx === -1) {
            if (window.EntraOpsReportUtils) {
                EntraOpsReportUtils.deepLinkNotFound("Tier breach path", pathId || [objectId, role, service, scopeId].filter(Boolean).join(" / "), "loaded breach paths");
            }
            return;
        }

        // The table is paged, so the target row may not be rendered yet. Grow the page window to
        // include it and re-render; without this the deep link would silently do nothing for any
        // starred row past the first page.
        if (idx >= state.breachLimit) {
            state.breachLimit = Math.ceil((idx + 1) / PAGE_STEP) * PAGE_STEP;
            renderBreachTable(filteredPaths());
        }

        // Record the expansion in state so it survives the next re-render, then reflect it in the DOM.
        state.openRows.add(rowKey(currentBreaches[idx]));

        const tbody = document.querySelector("#breachTable tbody");
        const tr = tbody.querySelector(`tr.breach-row[data-row="${idx}"]`);
        if (!tr) return;
        const detail = tbody.querySelector(`tr.detail-row[data-row="${idx}"]`);
        tr.classList.add("open");
        tr.setAttribute("aria-expanded", "true");
        if (detail) detail.classList.remove("hidden");
        tr.scrollIntoView({ behavior: "smooth", block: "center" });
        tr.classList.remove("eo-flash");
        void tr.offsetWidth;
        tr.classList.add("eo-flash");
    }

    function clearFiltersForDeepLink() {
        state.search = "";
        document.getElementById("search").value = "";
        systems.forEach((system) => state.systems.add(system));
        ["user", "serviceprincipal"].forEach((type) => state.types.add(type));
        document.querySelectorAll("#systemChecks input, #typeChecks input").forEach((checkbox) => { checkbox.checked = true; });
        state.tableFilter = null;
        updateFilterTag();
        render();
    }

    // ---- Table node filter -------------------------------------------------
    function setTableFilterFromNode(node) {
        // node.column + node.id map back to a path predicate.
        state.tableFilter = {
            column: node.column,
            id: node.id,
            label: `${COLUMNS[node.column].label}: ${node.name}`,
        };
        updateFilterTag();
        state.breachLimit = PAGE_STEP; // node filter changes the result set - restart paging
        renderBreachTable(filteredPaths());
        document
            .getElementById("breachTable")
            .scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function updateFilterTag() {
        const tag = document.getElementById("tableFilter");
        const clear = document.getElementById("clearFilter");
        if (state.tableFilter) {
            tag.textContent = "▣ " + state.tableFilter.label;
            tag.classList.remove("hidden");
            clear.classList.remove("hidden");
        } else {
            tag.classList.add("hidden");
            clear.classList.add("hidden");
        }
    }

    // ---- CSV export --------------------------------------------------------
    function exportCsv() {
        const cols = [
            ["objectName", "Object"],
            ["objectType", "Type"],
            ["objectTier", "ObjectTier"],
            ["system", "System"],
            ["role", "Role"],
            ["roleType", "RoleType"],
            ["roleIsPrivileged", "RoleIsPrivileged"],
            ["service", "Service"],
            ["serviceTier", "ServiceTier"],
            ["tier0Breach", "Tier0Breach"],
            ["assignmentId", "AssignmentId"],
            ["assignmentType", "AssignmentType"],
            ["assignmentSubType", "AssignmentSubType"],
            ["scopeName", "ScopeName"],
            ["scopeId", "ScopeId"],
            ["pimManaged", "PIMManaged"],
            ["pimAssignmentType", "PIMAssignmentType"],
            ["transitiveBy", "InheritedVia"],
            ["taggedBy", "ClassifiedBy"],
            ["taggedByRoleSystem", "ClassifiedInSystem"],
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
        currentBreaches.forEach((p) => {
            lines.push(cols.map((c) => csvCell(p[c[0]])).join(","));
        });
        const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "entraops-tier-breaches.csv";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ---- Helpers -----------------------------------------------------------
    function showTip(ev, html) {
        tooltip
            .classed("hidden", false)
            .html(html)
            .style("left", ev.clientX + 14 + "px")
            .style("top", ev.clientY + 14 + "px");
    }
    function hideTip() {
        tooltip.classed("hidden", true);
    }
    function truncate(s, n) {
        s = String(s);
        return s.length > n ? s.slice(0, n - 1) + "…" : s;
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

    // Resize changes the Sankey width only - the table is width independent, so redraw just the
    // diagram, and debounce it (a resize drag fires this handler dozens of times per second).
    window.addEventListener("resize", debounce(() => renderDiagram(), 180));
    window.addEventListener("hashchange", applyDeepLink);
    bindBreachTableEvents(); // delegated, bound once - the tbody element itself is never replaced
    render();
    applyDeepLink();
})();
