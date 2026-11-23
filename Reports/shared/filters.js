/*
 * Shared filter controls of the reporting apps (styles in shared/filters.css), as window.EntraOpsFilters:
 *   * pill / bindPills: facet pills with the number of matching items. A filter state is a plain object
 *     ({ tier: "", status: "" }); a click on a pill selects its value, a second click on it shows all again.
 *     A multi-select facet (pill option multi) holds a list instead ({ tier: [] }): a click adds or removes
 *     the value, and the "All" pill (value "") clears the list. An empty list shows all; use isSelected.
 *   * toggle: a pill without count for view options (for example the columns of a chart).
 *   * tierPill: a pill with the tier dot and color.
 *   * searchIcon: the icon of the search field (<label class="eo-search">).
 *   * collapsible: groups whose title collapses them to their summary, remembered in localStorage.
 * Pills are for filters with few values (tier, type, status, severity); filters with many values stay dropdowns.
 */
(function () {
    "use strict";

    function esc(value) {
        return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
    }

    // Whether a value is selected in a facet: single-select ("" for all) or multi-select (a list, empty for all).
    function isSelected(state, facet, value) {
        var current = state[facet];
        if (Array.isArray(current)) return value === "" ? current.length === 0 : current.indexOf(value) >= 0;
        return current === value;
    }

    // Whether an item value passes a facet: always when nothing is selected.
    function matchesFacet(state, facet, value) {
        var current = state[facet];
        if (Array.isArray(current)) return current.length === 0 || [].concat(value).some(function (item) { return current.indexOf(item) >= 0; });
        return !current || [].concat(value).indexOf(current) >= 0;
    }

    // A pill of a facet. options: cls (extra classes), icon (SVG content), prefix (HTML before the label),
    // title, multi (the facet is multi-select: its state is a list). A pill without matches is disabled
    // unless it is selected.
    function pill(state, facet, value, label, count, options) {
        options = options || {};
        var active = isSelected(state, facet, value);
        return '<button type="button" class="eo-pill' + (active ? " active" : "") + (options.cls ? " " + options.cls : "") + '" data-facet="' + esc(facet) + '" data-value="' + esc(value) +
            '" aria-pressed="' + active + '"' + (options.multi ? ' data-multi="true"' : "") + (options.title ? ' title="' + esc(options.title) + '"' : "") + (!count && !active ? " disabled" : "") + ">" +
            (options.icon ? '<svg class="eo-pill-icon" viewBox="0 0 16 16" aria-hidden="true">' + options.icon + "</svg>" : "") +
            (options.prefix || "") + "<span>" + esc(label) + '</span><span class="eo-pill-count">' + esc(count) + "</span></button>";
    }

    // A pill of a tier (ControlPlane, ManagementPlane, WorkloadPlane, UserAccess, Unclassified).
    function tierPill(state, facet, tier, label, count, options) {
        options = options || {};
        return pill(state, facet, tier, label, count, {
            cls: "eo-pill-tier eo-tier-" + String(tier || "unclassified").toLowerCase() + (options.cls ? " " + options.cls : ""),
            prefix: '<span class="eo-tier-dot" aria-hidden="true"></span>', title: options.title, multi: options.multi
        });
    }

    // A pill without count that switches a view option on or off (data-toggle, data-value); the app handles the click.
    function toggle(name, value, label, on, options) {
        options = options || {};
        return '<button type="button" class="eo-pill eo-pill-toggle' + (on ? " active" : "") + (options.cls ? " " + options.cls : "") + '" data-toggle="' + esc(name) + '" data-value="' + esc(value) +
            '" aria-pressed="' + !!on + '"' + (options.title ? ' title="' + esc(options.title) + '"' : "") + (options.disabled ? " disabled" : "") + ">" +
            (options.prefix || "") + "<span>" + esc(label) + "</span></button>";
    }

    // Counts of the values of a facet among the items that match all other filters: { total, counts }.
    // matches(item, skipFacet) tells whether an item matches the filters except skipFacet; valueOf(item)
    // returns the value of the facet (or a list of values). With keyOf(item), items of the same key (for example
    // one object listed once per RBAC system) are counted once per value and once in the total.
    function facetCounts(items, facet, matches, valueOf, keyOf) {
        // Facet values of the tenant as keys: maps without prototype.
        var counts = Object.create(null), total = 0, seen = Object.create(null);
        items.forEach(function (item) {
            if (!matches(item, facet)) return;
            var key = keyOf ? "k:" + keyOf(item) : null;
            if (!key || !seen[key]) total++;
            if (key) seen[key] = seen[key] || {};
            [].concat(valueOf(item)).forEach(function (value) {
                if (value == null || value === "") return;
                if (key) {
                    if (seen[key]["v:" + value]) return;
                    seen[key]["v:" + value] = true;
                }
                counts[value] = (counts[value] || 0) + 1;
            });
        });
        return { total: total, counts: counts };
    }

    function bindPills(container, state, onChange) {
        container.addEventListener("click", function (ev) {
            var button = ev.target.closest ? ev.target.closest("[data-facet]") : null;
            if (!button || button.disabled || !container.contains(button)) return;
            var facet = button.getAttribute("data-facet"), value = button.getAttribute("data-value");
            if (button.hasAttribute("data-multi") || Array.isArray(state[facet])) {
                var list = Array.isArray(state[facet]) ? state[facet].slice() : [];
                var index = list.indexOf(value);
                if (value === "") list = [];
                else if (index >= 0) list.splice(index, 1);
                else list.push(value);
                state[facet] = list;
            } else {
                state[facet] = state[facet] === value ? "" : value;
            }
            onChange(facet, state[facet]);
            // The pills are rendered again: keep the keyboard focus on the pill that was used.
            var quote = function (text) { return window.CSS && CSS.escape ? CSS.escape(text) : String(text).replace(/["\\]/g, "\\$&"); };
            var again = container.querySelector('[data-facet="' + quote(facet) + '"][data-value="' + quote(value) + '"]');
            if (again && !again.disabled) again.focus();
        });
    }

    var searchIcon = '<svg class="eo-search-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6.5 1a5.5 5.5 0 0 1 4.38 8.83l3.65 3.64a.75.75 0 0 1-1.06 1.06l-3.64-3.65A5.5 5.5 0 1 1 6.5 1Zm0 1.5a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z" /></svg>';

    // Collapsible groups, remembered in localStorage under storageKey (one key per report and list).
    //   var groups = EntraOpsFilters.collapsible("entraops.<report>.<list>.collapsed", render);
    //   html += groups.head(key, title, summaryHtml) + groups.body(key, contentHtml);   inside groups.open(key) ... "</div>"
    //   groups.bind(listContainer); groups.setAll(visibleKeys, collapsed); groups.allCollapsed(visibleKeys)
    function collapsible(storageKey, onChange) {
        // Group keys can be names of the tenant (for example a catalog): a map without prototype.
        var collapsed = Object.create(null);
        try {
            (JSON.parse(localStorage.getItem(storageKey) || "[]") || []).forEach(function (key) { collapsed[key] = true; });
        } catch (_) { collapsed = Object.create(null); }

        function save() {
            try { localStorage.setItem(storageKey, JSON.stringify(Object.keys(collapsed))); } catch (_) { /* private mode: this page only */ }
        }

        function bodyId(key) { return "eoGroup-" + storageKey.replace(/[^A-Za-z0-9_-]/g, "_") + "-" + String(key).replace(/[^A-Za-z0-9_-]/g, "_"); }

        function setAll(keys, value) {
            keys.forEach(function (key) {
                if (value) collapsed[key] = true;
                else delete collapsed[key];
            });
            save();
            if (onChange) onChange();
        }

        return {
            isCollapsed: function (key) { return collapsed[key] === true; },
            allCollapsed: function (keys) { return keys.length > 0 && keys.every(function (key) { return collapsed[key]; }); },
            setAll: setAll,
            // The opening tag of a group; close it with "</div>".
            open: function (key, extraClass) {
                return '<div class="eo-group' + (collapsed[key] ? " collapsed" : "") + (extraClass ? " " + extraClass : "") + '" data-group="' + esc(key) + '">';
            },
            head: function (key, title, summaryHtml) {
                return '<div class="eo-group-head"><button type="button" class="eo-group-toggle" data-group-toggle="' + esc(key) + '" aria-expanded="' + !collapsed[key] + '" aria-controls="' + esc(bodyId(key)) + '">' +
                    '<svg class="eo-group-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 6l4 4 4-4" /></svg><span class="eo-group-title">' + esc(title) + "</span></button>" +
                    (summaryHtml ? '<span class="eo-group-meta">' + summaryHtml + "</span>" : "") + "</div>";
            },
            body: function (key, html) {
                return '<div class="eo-group-body" id="' + esc(bodyId(key)) + '"' + (collapsed[key] ? " hidden" : "") + ">" + html + "</div>";
            },
            // Toggles a group by its title and keeps the keyboard focus on the title after the list re-renders.
            bind: function (container) {
                container.addEventListener("click", function (ev) {
                    var toggle = ev.target.closest ? ev.target.closest("[data-group-toggle]") : null;
                    if (!toggle || !container.contains(toggle)) return;
                    var key = toggle.getAttribute("data-group-toggle");
                    setAll([key], !collapsed[key]);
                    var again = container.querySelector('[data-group-toggle="' + (window.CSS && CSS.escape ? CSS.escape(key) : key) + '"]');
                    if (again) again.focus();
                });
            }
        };
    }

    window.EntraOpsFilters = {
        esc: esc, pill: pill, tierPill: tierPill, toggle: toggle, isSelected: isSelected, matchesFacet: matchesFacet,
        facetCounts: facetCounts, bindPills: bindPills, searchIcon: searchIcon, collapsible: collapsible
    };
})();
