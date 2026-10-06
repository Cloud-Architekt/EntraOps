/*
 * EntraOps Classification Explorer - App shell, router and drawer
 */
window.EOCE = window.EOCE || {};

EOCE.app = (function () {
    var appEl, drawerEl, backdropEl, titleEl, bodyEl, eyebrowEl;
    var current = null;

    // ---- Drawer ----------------------------------------------------------
    function openDrawer(eyebrow, title, html) {
        eyebrowEl.innerHTML = eyebrow || '';
        titleEl.innerHTML = title || '';
        bodyEl.innerHTML = html || '';
        drawerEl.classList.add('open');
        drawerEl.setAttribute('aria-hidden', 'false');
        backdropEl.classList.add('open');
        bodyEl.scrollTop = 0;
        EOCE.a11y.openDialog(drawerEl, document.getElementById('drawerClose'));
    }
    function closeDrawer() {
        var wasOpen = drawerEl.classList.contains('open');
        drawerEl.classList.remove('open');
        drawerEl.setAttribute('aria-hidden', 'true');
        backdropEl.classList.remove('open');
        if (wasOpen) EOCE.a11y.closeDialog(drawerEl);
    }

    // ---- Rendering helpers ----------------------------------------------
    function setLoading(msg) {
        appEl.innerHTML = '<div class="loading"><div class="spinner"></div>' + (msg || 'Loading&hellip;') + '</div>';
    }
    function setError(err) {
        appEl.innerHTML =
            '<div class="error-box"><strong>Unable to load data.</strong><br>' +
            EOCE.util.escapeHtml(err && err.message ? err.message : String(err)) +
            '<br><br>This app runs entirely from the classification data embedded in data/classification-data.js. ' +
            'Re-run <code>' + EOCE.util.escapeHtml(EOCE.GENERATOR_COMMAND) + '</code> to refresh it.</div>';
    }

    // ---- Routing ---------------------------------------------------------
    function resolveRoute(route) {
        switch (route) {
            case 'overview': return { route: route, view: EOCE.views.tiermap };
            case 'model': return { route: route, view: EOCE.views.model };
            case 'roles': return { route: route, view: EOCE.views.roles };
            case 'actions': return { route: route, view: EOCE.views.actions };
            case 'permissions': return { route: route, view: EOCE.views.permissions };
            case 'scoped': return { route: route, view: EOCE.views.scoped };
            case 'overwrites': return { route: route, view: EOCE.views.overwrites };
            case 'history': return { route: route, view: EOCE.isEntraOpsMode() ? null : EOCE.views.history };
            case 'customize': return { route: route, view: EOCE.isEntraOpsMode() ? EOCE.views.customize : null };
            case 'compare': return { route: route, view: EOCE.isEntraOpsMode() ? EOCE.views.compare : null };
            case 'attackpaths': return { route: route, view: EOCE.views.attackpaths };
            case 'dashboard':
            default: return { route: 'dashboard', view: EOCE.views.overview };
        }
    }

    function parseHash() {
        var h = (location.hash || '#dashboard').replace(/^#/, '');
        var parts = h.split('/');
        var params = parts.slice(1).map(function (part) {
            try { return decodeURIComponent(part); } catch (e) { return part; }
        });
        return { route: parts[0] || 'dashboard', params: params };
    }

    function setActiveNav(route) {
        var items = document.querySelectorAll('.nav-item[data-route]');
        items.forEach(function (el) {
            var active = el.getAttribute('data-route') === route;
            el.classList.toggle('active', active);
            if (active) el.setAttribute('aria-current', 'page');
            else el.removeAttribute('aria-current');
        });
    }

    function navigate() {
        closeDrawer();
        var parsed = parseHash();
        // Role Comparison is a contextual blade on top of the Roles page, not a
        // dedicated route: '#rolecompare/<sysKey>:<roleId>/...' opens it directly
        // when Roles is already the active view (the common case - triggered from
        // the Roles table's compare checkboxes or a role's details drawer), or
        // renders Roles first on a cold load / bookmarked deep link.
        if (parsed.route === 'rolecompare') {
            if (current === EOCE.views.roles && EOCE.views.roles.all && EOCE.views.roles.all.length && window.EOCE.roleCompare) {
                EOCE.roleCompare.open(parsed.params);
                return;
            }
            setActiveNav('roles');
            document.getElementById('nav').classList.remove('open');
            current = EOCE.views.roles;
            setLoading();
            Promise.resolve()
                .then(function () { return EOCE.views.roles.render(appEl, []); })
                .then(function () { if (window.EOCE.roleCompare) EOCE.roleCompare.open(parsed.params); })
                .catch(setError);
            window.scrollTo(0, 0);
            return;
        }
        var resolved = resolveRoute(parsed.route);
        var view = resolved.view;
        if (!view) { setError(new Error('View not found: ' + parsed.route)); return; }
        setActiveNav(resolved.route);
        document.getElementById('nav').classList.remove('open');
        current = view;
        setLoading();
        Promise.resolve()
            .then(function () { return view.render(appEl, parsed.params); })
            .catch(setError);
        window.scrollTo(0, 0);
    }

    function go(hash) {
        if (location.hash === '#' + hash) navigate();
        else location.hash = hash;
    }

    // ---- Sidebar counts --------------------------------------------------
    function updateCounts() {
        // Attack paths load on demand (ensureAttackPaths fills the badge); don't show "0" before that.
        var elA = document.getElementById('cnt-attack');
        if (elA && EOCE.ATTACK_PATHS && EOCE.ATTACK_PATHS.length) elA.textContent = EOCE.util.formatNumber(EOCE.ATTACK_PATHS.length);

        var rolePaths = EOCE.rolesSystemKeys().map(function (k) { return EOCE.RBAC_SYSTEMS[k].file; });
        Promise.all([
            EOCE.data.loadAll(rolePaths),
            EOCE.data.load(EOCE.RBAC_SYSTEMS.Defender.definition)
        ]).then(function (res) {
            var sets = res[0], defenderDef = res[1];
            var roles = 0, actions = 0;
            sets.forEach(function (s) {
                roles += s.length;
                s.forEach(function (r) { actions += EOCE.rolePerms(r).length; });
            });
            // Defender contributes derived role actions (distinct microsoft.xdr/* operations).
            var defActions = {};
            (defenderDef || []).forEach(function (tierObj) {
                (tierObj.TierLevelDefinition || []).forEach(function (def) {
                    (def.RoleDefinitionActions || []).forEach(function (a) { defActions[a] = true; });
                });
            });
            actions += Object.keys(defActions).length;
            var el1 = document.getElementById('cnt-roles');
            var el2 = document.getElementById('cnt-actions');
            if (el1) el1.textContent = EOCE.util.formatNumber(roles);
            if (el2) el2.textContent = EOCE.util.formatNumber(actions);
        }).catch(function () { });

        var permPaths = Object.keys(EOCE.PERMISSION_SETS).map(function (k) { return EOCE.PERMISSION_SETS[k].file; });
        EOCE.data.loadAll(permPaths).then(function (sets) {
            var n = 0; sets.forEach(function (s) { n += s.length; });
            var el = document.getElementById('cnt-perms');
            if (el) el.textContent = EOCE.util.formatNumber(n);
        }).catch(function () { });

        EOCE.data.load(EOCE.OVERWRITES_FILE).then(function (o) {
            var el = document.getElementById('cnt-ovr');
            if (el) el.textContent = EOCE.util.formatNumber(o.length);
        }).catch(function () { });
    }

    function classificationNotifications(history) {
        history = history || window.EOCE_NOTIFICATION_DATA || window.EOCE_HISTORY;
        if (!history || !history.sources) return { id: 'none', items: [] };
        var notification = history.notification || null;
        var notificationSources = notification && Array.isArray(notification.sourceKeys) ? notification.sourceKeys : null;
        if (notificationSources && notificationSources.length === 0) {
            return { id: notification.changeSetId || 'none', items: [] };
        }
        var items = [];
        var newestDate = '';
        Object.keys(history.sources).forEach(function (sourceKey) {
            if (notificationSources && notificationSources.indexOf(sourceKey) === -1) return;
            var source = history.sources[sourceKey];
            var commits = source && Array.isArray(source.commits) ? source.commits : [];
            if (!commits.length) return;
            var commit = commits[commits.length - 1];
            if (commit.date > newestDate) newestDate = commit.date;
            var isPermission = source.kind === 'permissions';
            var resourceHref = function (entry) {
                return isPermission
                    ? '#permissions/all/' + encodeURIComponent(entry.name || '') + '/' + encodeURIComponent(entry.id || '')
                    : '#roles/' + encodeURIComponent(sourceKey) + '/' + encodeURIComponent(entry.id || '');
            };
            ['added', 'removed', 'changed'].forEach(function (changeKey) {
                (commit[changeKey] || []).forEach(function (entry) {
                    var tierChanged = entry.oldTier && entry.newTier && entry.oldTier !== entry.newTier;
                    var actionChanged = (entry.actionsAdded && entry.actionsAdded.length) || (entry.actionsRemoved && entry.actionsRemoved.length);
                    var changeLabel = changeKey.charAt(0).toUpperCase() + changeKey.slice(1);
                    if (changeKey !== 'changed' || isPermission || tierChanged) {
                        items.push({
                            kind: isPermission ? 'API permission' : 'Role',
                            change: changeLabel,
                            title: (entry.name || entry.id) + ' ' + changeKey,
                            detail: entry.oldTier && entry.newTier ? entry.oldTier + ' -> ' + entry.newTier : source.label,
                            href: resourceHref(entry)
                        });
                    }
                    if (!isPermission) {
                        (entry.actions || entry.actionsAdded || []).forEach(function (action) {
                            items.push({ kind: 'Role action', change: 'Added', title: action, detail: 'Role: ' + (entry.name || entry.id), href: '#actions/' + encodeURIComponent(sourceKey) + '/' + encodeURIComponent(action) });
                        });
                        (entry.actionsRemoved || []).forEach(function (action) {
                            items.push({ kind: 'Role action', change: 'Removed', title: action, detail: 'Role: ' + (entry.name || entry.id), href: '#actions/' + encodeURIComponent(sourceKey) + '/' + encodeURIComponent(action) });
                        });
                    }
                });
            });
        });
        return { id: notification && notification.changeSetId || newestDate || 'none', items: items };
    }

    // ---- Init ------------------------------------------------------------
    function init() {
        if (window.EOReview) {
            EOReview.init({ app: 'ClassificationExplorer', appLabel: 'Classification Explorer' });
        }
        appEl = document.getElementById('app');
        drawerEl = document.getElementById('drawer');
        backdropEl = document.getElementById('drawerBackdrop');
        titleEl = document.getElementById('drawerTitle');
        bodyEl = document.getElementById('drawerBody');
        eyebrowEl = document.getElementById('drawerEyebrow');

        if (EOCE.deploymentError) {
            setError(new Error(EOCE.deploymentError));
            return;
        }

        if (window.EONotifications) {
            var notifications = classificationNotifications();
            EONotifications.init({ appId: 'ClassificationExplorer', changeSetId: notifications.id, items: notifications.items });
        }

        document.getElementById('drawerClose').addEventListener('click', closeDrawer);
        backdropEl.addEventListener('click', closeDrawer);
        document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeDrawer(); });

        document.querySelectorAll('.nav-item[data-route]').forEach(function (el) {
            el.setAttribute('role', 'link');
            el.setAttribute('tabindex', '0');
            el.addEventListener('click', function () { go(el.getAttribute('data-route')); });
            el.addEventListener('keydown', function (e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                go(el.getAttribute('data-route'));
            });
        });
        document.getElementById('navToggle').addEventListener('click', function () {
            document.getElementById('nav').classList.toggle('open');
        });

        // Mode-gated elements: any element (nav item, group label, appbar control, ...)
        // tagged data-mode="standalone" / data-mode="entraops" is hidden outside that
        // mode. Lets index.html stay byte-identical between the two deployments.
        document.querySelectorAll('[data-mode]').forEach(function (el) {
            if (el.getAttribute('data-mode') !== EOCE.MODE) el.hidden = true;
        });

        document.getElementById('docsLink').href = EOCE.DOCS.enterpriseAccessModel;
        document.getElementById('repoLink').href = EOCE.DOCS.entraOpsRepo;
        document.getElementById('footerAuthorLink').href = EOCE.DOCS.blog;
        document.getElementById('footerDisclosureLink').href = EOCE.DOCS.disclosure;

        // Entraops mode only: classification source selector (built-in template vs
        // tenant-specific variant) and portal-wide navigation (sibling reporting apps).
        if (EOCE.isEntraOpsMode()) {
            var variantPicker = document.getElementById('variantPicker');
            var variantSelect = document.getElementById('variantSelect');
            if (variantPicker && variantSelect) {
                var options = EOCE.variantOptions();
                if (options.length > 1) {
                    options.forEach(function (o) {
                        var opt = document.createElement('option');
                        opt.value = o.key;
                        opt.textContent = o.label;
                        variantSelect.appendChild(opt);
                    });
                    variantSelect.value = EOCE.getVariant();
                    variantSelect.addEventListener('change', function () {
                        EOCE.setVariant(variantSelect.value);
                        navigate();
                        updateCounts();
                    });
                    variantPicker.hidden = false;
                }
            }
            renderPortalNav();
        }

        window.addEventListener('hashchange', navigate);
        navigate();
        updateCounts();
    }

    // Portal-wide navigation: when embedded in the EntraOps reporting portal, sibling
    // apps live in sibling folders under Reports/ (see EOCE.PORTAL_NAV in config.js).
    // Injected client-side (rather than hardcoded in index.html) so index.html stays
    // byte-identical between the standalone and entraops copies of this app.
    function renderPortalNav() {
        var nav = document.getElementById('nav');
        var anchor = document.getElementById('navCollapseToggle');
        if (!nav || !anchor || !EOCE.PORTAL_NAV || !EOCE.PORTAL_NAV.length) return;
        var html = '<div class="nav-group-label">' + EOCE.util.escapeHtml(EOCE.PORTAL_NAV_LABEL || 'Privileged EAM Reporting') + '</div>';
        EOCE.PORTAL_NAV.forEach(function (item) {
            if (item.current) {
                html += '<div class="nav-item active"><span class="ico">' + item.icon + '</span><span>' + EOCE.util.escapeHtml(item.label) + '</span></div>';
            } else {
                html += '<a class="nav-item' + (item.sub ? ' nav-subitem' : '') + '" href="' + EOCE.util.escapeHtml(item.href) + '"><span class="ico">' + item.icon + '</span><span>' + EOCE.util.escapeHtml(item.label) + '</span></a>';
            }
        });
        anchor.insertAdjacentHTML('afterend', html);
    }

    document.addEventListener('DOMContentLoaded', init);

    return { openDrawer: openDrawer, closeDrawer: closeDrawer, go: go, setError: setError };
})();
