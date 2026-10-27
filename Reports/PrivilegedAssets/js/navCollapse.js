/*
 * Privileged EAM Reporting - collapsible navigation rail
 *
 * Lets the left navigation rail be minimized to an icon-only strip so
 * investigations have more room on the main page. State is shared across all
 * reporting apps (same localStorage key, same origin) so the preference
 * follows the user when navigating between apps. Icons always stay visible;
 * only the text labels, group headers and counters are hidden when collapsed
 * (native title tooltips are added so the labels remain discoverable on hover).
 *
 * This file is intentionally identical in every sub-app (self-contained apps
 * by design) - see js/review.js for the same pattern.
 */
(function () {
    "use strict";

    var KEY = "entraops.navCollapsed";

    function apply(collapsed) {
        var nav = document.getElementById("nav");
        var btn = document.getElementById("navCollapseToggle");
        if (!nav) return;
        nav.classList.toggle("collapsed", collapsed);
        if (btn) {
            btn.innerHTML = collapsed ? "&#187;" : "&#171;";
            btn.title = collapsed ? "Expand navigation" : "Collapse navigation";
            btn.setAttribute("aria-label", collapsed ? "Expand navigation" : "Collapse navigation");
            btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
        }
        // Native tooltips for icon-only items - cache the label once so
        // re-collapsing doesn't re-read the (by then hidden) label spans.
        nav.querySelectorAll(".nav-item").forEach(function (el) {
            if (collapsed) {
                if (!el.dataset.eoNavLabel) {
                    var label = Array.prototype.slice.call(el.querySelectorAll("span"))
                        .filter(function (s) { return !s.classList.contains("ico") && !s.classList.contains("count"); })
                        .map(function (s) { return s.textContent.trim(); })
                        .filter(Boolean)
                        .join(" ");
                    el.dataset.eoNavLabel = label || el.textContent.trim();
                }
                el.title = el.dataset.eoNavLabel;
            } else {
                el.removeAttribute("title");
            }
        });
    }

    function init() {
        var nav = document.getElementById("nav");
        var btn = document.getElementById("navCollapseToggle");
        if (!nav || !btn) return;

        var stored = null;
        try {
            stored = localStorage.getItem(KEY);
        } catch (e) { /* private mode */ }
        apply(stored === "1");

        btn.addEventListener("click", function () {
            var next = !nav.classList.contains("collapsed");
            apply(next);
            try {
                localStorage.setItem(KEY, next ? "1" : "0");
            } catch (e) { /* private mode */ }
        });

        // Keep multiple open tabs/apps in sync when the preference changes elsewhere.
        window.addEventListener("storage", function (e) {
            if (e.key === KEY) apply(e.newValue === "1");
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
