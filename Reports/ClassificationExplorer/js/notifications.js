/* Shared EntraOps report notification panel. */
(function (global) {
    "use strict";

    function escapeHtml(value) {
        return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
        });
    }

    function init(options) {
        var button = document.getElementById("notificationButton");
        if (!button) return;

        var items = Array.isArray(options.items) ? options.items : [];
        var changeSetId = String(options.changeSetId || "none");
        var loadPromise = null;
        var storageKey = "entraops.notifications.read." + options.appId;
        var isRead = false;
        try { isRead = localStorage.getItem(storageKey) === changeSetId; } catch (e) { /* private mode */ }
        var backdrop = document.createElement("div");
        backdrop.className = "eo-notification-backdrop";
        var panel = document.createElement("aside");
        panel.className = "eo-notification-panel";
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-modal", "true");
        panel.setAttribute("aria-hidden", "true");
        panel.setAttribute("aria-labelledby", "notificationTitle");
        document.body.appendChild(backdrop);
        document.body.appendChild(panel);

        function updateCount() {
            var count = isRead ? 0 : items.length;
            var badge = button.querySelector(".eo-notification-count");
            badge.textContent = count > 99 ? "99+" : String(count);
            badge.hidden = count === 0;
            button.setAttribute("aria-label", count ? count + " unread changes" : "No unread changes");
        }

        function markRead() {
            isRead = true;
            try { localStorage.setItem(storageKey, changeSetId); } catch (e) { /* private mode */ }
            updateCount();
        }

        function load() {
            if (!options.load) return Promise.resolve();
            if (loadPromise) return loadPromise;
            loadPromise = Promise.resolve()
                .then(function () { return options.load(); })
                .then(function (result) {
                    result = result || {};
                    items = Array.isArray(result.items) ? result.items : [];
                    changeSetId = String(result.changeSetId || result.id || "none");
                    try { isRead = localStorage.getItem(storageKey) === changeSetId; } catch (e) { /* private mode */ }
                    updateCount();
                    return result;
                })
                .catch(function (error) {
                    loadPromise = null;
                    throw error;
                });
            return loadPromise;
        }

        function close() {
            var wasOpen = panel.classList.contains("open");
            panel.classList.remove("open");
            backdrop.classList.remove("open");
            panel.setAttribute("aria-hidden", "true");
            if (wasOpen) button.focus();
        }

        function renderItem(item, grouped) {
            var label = grouped ? escapeHtml(item.kind || "Change") + (item.kind === "Role action" ? ' · ' + escapeHtml(item.change || "") : "")
                : escapeHtml(item.kind || "Change") + ' · ' + escapeHtml(item.change || "Changed");
            return '<a class="eo-notification-item" href="' + escapeHtml(item.href || "#") + '" data-notification-link>' +
                '<span class="eo-notification-kind">' + label + '</span>' +
                '<span class="eo-notification-title">' + escapeHtml(item.title || "Classification changed") + '</span>' +
                (item.detail ? '<span class="eo-notification-detail">' + escapeHtml(item.detail) + '</span>' : "") +
                '</a>';
        }

        function renderGrouped() {
            var sections = [];
            var byKey = {};
            items.forEach(function (item) {
                var sectionName = item.section || "Other changes";
                var section = byKey[sectionName];
                if (!section) {
                    section = byKey[sectionName] = { name: sectionName, count: 0, groups: [], groupByKey: {} };
                    sections.push(section);
                }
                var groupName = item.group || "Changed";
                var group = section.groupByKey[groupName];
                if (!group) {
                    group = section.groupByKey[groupName] = { name: groupName, items: [] };
                    section.groups.push(group);
                }
                group.items.push(item);
                section.count++;
            });
            return sections.map(function (section) {
                return '<section class="eo-notification-section">' +
                    '<h3 class="eo-notification-section-title">' + escapeHtml(section.name) + '<span>' + section.count + '</span></h3>' +
                    section.groups.map(function (group) {
                        return '<h4 class="eo-notification-group-title">' + escapeHtml(group.name) + '<span>' + group.items.length + '</span></h4>' +
                            group.items.map(function (item) { return renderItem(item, true); }).join("");
                    }).join("") +
                    '</section>';
            }).join("");
        }

        function render() {
            var grouped = items.some(function (item) { return item.section || item.group; });
            var body = !items.length
                ? '<div class="eo-notification-empty">No changes were detected in the latest report.</div>'
                : grouped ? renderGrouped() : items.map(function (item) { return renderItem(item, false); }).join("");
            panel.innerHTML =
                '<div class="eo-notification-head"><div><strong id="notificationTitle">Recent changes</strong>' +
                '<span>Since the previous classification report</span></div>' +
                '<button type="button" class="eo-notification-close" aria-label="Close notifications">&#10005;</button></div>' +
                '<div class="eo-notification-body">' + body + '</div>';
            panel.querySelector(".eo-notification-close").addEventListener("click", close);
            panel.querySelectorAll("[data-notification-link]").forEach(function (link) {
                link.addEventListener("click", markRead);
            });
        }

        button.addEventListener("click", function () {
            load().catch(function () { items = []; }).then(function () {
                render();
                panel.classList.add("open");
                backdrop.classList.add("open");
                panel.setAttribute("aria-hidden", "false");
                panel.querySelector(".eo-notification-close").focus();
                markRead();
            });
        });
        backdrop.addEventListener("click", close);
        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape") close();
        });
        window.addEventListener("hashchange", function () {
            if (panel.classList.contains("open")) markRead();
            close();
        });
        updateCount();
    }

    global.EONotifications = { init: init };
})(window);
