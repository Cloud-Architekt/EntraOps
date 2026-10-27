// EntraOps Docs - client-side search across every page's Markdown content.
//
// Builds a lightweight search index once (per page load) from window.EODOCS_CONTENT
// (the same embedded Markdown bundle js/markdown.js renders for the current page - see
// Docs/Update-EntraOpsDocsContent.ps1) by rendering every OTHER page's Markdown into a
// detached container and walking its headings, so indexed anchors always match what
// DocsMD.render() actually produces (no separate/divergent heading-id logic to keep in
// sync). Works fully offline, no fetch()/server required, consistent with the rest of
// EntraOps Docs and the Reports/* reporting apps.
(function () {
    "use strict";

    // Docs root, derived from this script's own URL (<docs>/js/search.js): result links then resolve correctly
    // from pages at any depth, e.g. get-started/migration-guide/, also when the docs are opened from file://.
    var scriptSrc = document.currentScript && document.currentScript.src;

    // Content keys (window.EODOCS_CONTENT) -> page metadata. "overview" (the Docs home page
    // intro) has no headings to index and is intentionally omitted.
    var ROUTES = {
        "get-started": { title: "Get Started", folder: "get-started", bodyPage: "get-started" },
        "migration-guide": { title: "Migration guide", folder: "get-started/migration-guide", bodyPage: "migration-guide" },
        "core": { title: "Core", folder: "core", bodyPage: "core" },
        "tenant-governance": { title: "Tenant Governance", folder: "tenant-governance", bodyPage: "tenant-governance" },
        "privileged-eam": { title: "Privileged EAM", folder: "privileged-eam", bodyPage: "privileged-eam" },
        "service-em": { title: "Service EM", folder: "service-em", bodyPage: "service-em" },
        "reportings": { title: "Reportings", folder: "reportings", bodyPage: "reportings" },
        "changelog": { title: "Changelog", folder: "changelog", bodyPage: "changelog" }
    };

    var index = null;

    function esc(s) {
        return String(s == null ? "" : s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }

    function isAtDocsRoot() {
        return document.body.getAttribute("data-page") === "home";
    }

    function hrefFor(contentKey, id) {
        var route = ROUTES[contentKey];
        var path = route.folder + "/index.html#" + id;
        if (scriptSrc) {
            try {
                return new URL("../" + path, scriptSrc).href;
            } catch (e) {
                // Fall back to the relative link below
            }
        }
        var base = isAtDocsRoot() ? "" : "../";
        return base + path;
    }

    function buildIndex() {
        index = [];
        if (!window.EODOCS_CONTENT || !window.DocsMD) return;
        Object.keys(ROUTES).forEach(function (key) {
            var md = window.EODOCS_CONTENT[key];
            if (!md) return;
            // Match js/app.js: each page's own page-head already renders an <h1> title, so
            // the leading "# Title" line of the Markdown source is stripped before rendering
            // there - strip it here too, or the indexed heading ids wouldn't match the ids
            // that actually exist on the real page (a search hit on the page title would then
            // link to a non-existent anchor).
            md = md.replace(/^\s*#\s+.+(?:\r?\n)+/, "");
            var container = document.createElement("div");
            container.innerHTML = DocsMD.render(md);
            container.querySelectorAll("h1[id], h2[id], h3[id]").forEach(function (h) {
                var text = "";
                var el = h.nextElementSibling;
                while (el && !/^H[1-3]$/.test(el.tagName)) {
                    text += " " + el.textContent;
                    el = el.nextElementSibling;
                }
                index.push({
                    page: key,
                    id: h.id,
                    title: h.textContent.trim(),
                    text: text.replace(/\s+/g, " ").trim()
                });
            });
        });
    }

    function highlight(raw, query) {
        var i = raw.toLowerCase().indexOf(query.toLowerCase());
        if (i === -1) return esc(raw);
        return esc(raw.slice(0, i)) + "<mark>" + esc(raw.slice(i, i + query.length)) + "</mark>" + esc(raw.slice(i + query.length));
    }

    function snippetFor(entry, query) {
        var text = entry.text;
        var i = text.toLowerCase().indexOf(query.toLowerCase());
        if (i === -1) return esc(text.slice(0, 140)) + (text.length > 140 ? "\u2026" : "");
        var start = Math.max(0, i - 50);
        var end = Math.min(text.length, i + query.length + 90);
        return (start > 0 ? "\u2026" : "") + highlight(text.slice(start, end), query) + (end < text.length ? "\u2026" : "");
    }

    function search(query) {
        if (!index) buildIndex();
        var q = query.trim();
        if (q.length < 2) return [];
        var qLower = q.toLowerCase();
        var results = [];
        index.forEach(function (entry) {
            var titleHit = entry.title.toLowerCase().indexOf(qLower) !== -1;
            var textHit = entry.text.toLowerCase().indexOf(qLower) !== -1;
            if (!titleHit && !textHit) return;
            results.push({ entry: entry, score: titleHit ? 0 : 1 });
        });
        results.sort(function (a, b) { return a.score - b.score; });
        return results.slice(0, 20).map(function (r) { return r.entry; });
    }

    function onReady(fn) {
        if (document.readyState !== "loading") fn();
        else document.addEventListener("DOMContentLoaded", fn);
    }

    onReady(function () {
        var input = document.getElementById("docsSearchInput");
        var panel = document.getElementById("docsSearchResults");
        if (!input || !panel) return;

        var activeIndex = -1;

        function render(query, results) {
            if (!results.length) {
                panel.innerHTML = '<div class="docs-search-empty">No results for &ldquo;' + esc(query) + '&rdquo;</div>';
                panel.hidden = false;
                activeIndex = -1;
                return;
            }
            panel.innerHTML = results.map(function (entry, i) {
                var route = ROUTES[entry.page];
                return '<a class="docs-search-result' + (i === 0 ? " active" : "") + '" href="' + hrefFor(entry.page, entry.id) + '">' +
                    '<div class="docs-search-result-title">' + highlight(entry.title, query) +
                    '<span class="docs-search-badge">' + esc(route.title) + '</span></div>' +
                    '<div class="docs-search-result-snippet">' + snippetFor(entry, query) + '</div>' +
                    '</a>';
            }).join("");
            activeIndex = 0;
            panel.hidden = false;
        }

        function close() {
            panel.hidden = true;
            activeIndex = -1;
        }

        function setActive(i) {
            var results = panel.querySelectorAll(".docs-search-result");
            if (!results.length) return;
            i = (i + results.length) % results.length;
            results.forEach(function (r) { r.classList.remove("active"); });
            results[i].classList.add("active");
            results[i].scrollIntoView({ block: "nearest" });
            activeIndex = i;
        }

        input.addEventListener("input", function () {
            var query = input.value;
            if (!query.trim()) { close(); return; }
            render(query, search(query));
        });

        input.addEventListener("keydown", function (ev) {
            var results = panel.querySelectorAll(".docs-search-result");
            if (ev.key === "ArrowDown") { ev.preventDefault(); if (!panel.hidden) setActive(activeIndex + 1); }
            else if (ev.key === "ArrowUp") { ev.preventDefault(); if (!panel.hidden) setActive(activeIndex - 1); }
            else if (ev.key === "Enter") {
                if (!panel.hidden && results[activeIndex]) {
                    ev.preventDefault();
                    location.href = results[activeIndex].getAttribute("href");
                }
            } else if (ev.key === "Escape") {
                close();
                input.blur();
            }
        });

        input.addEventListener("focus", function () {
            if (input.value.trim() && !panel.querySelector(".docs-search-result, .docs-search-empty")) {
                render(input.value, search(input.value));
            } else if (input.value.trim()) {
                panel.hidden = false;
            }
        });

        document.addEventListener("click", function (ev) {
            if (!ev.target.closest(".docs-search")) close();
        });

        // "/" focuses search from anywhere on the page (unless already typing elsewhere).
        document.addEventListener("keydown", function (ev) {
            if (ev.key !== "/" || ev.target === input) return;
            var tag = ev.target.tagName;
            if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || ev.target.isContentEditable) return;
            ev.preventDefault();
            input.focus();
        });
    });
})();
