/*
 * EntraOps Classification Explorer - Role Comparison blade
 *
 * Contextual comparison (not a dedicated page): roles are selected via the
 * compare checkboxes in the Roles table (js/views/roles.js) or imported from
 * the Review list, then compared side by side in a full-screen blade/modal -
 * in entraops mode this mirrors the EAM Dashboard's principal comparison
 * pattern for consistency across the reporting apps.
 *
 * Reuses EOCE.views.roles.all (the Roles table's already-loaded role rows) as
 * its single source of truth instead of loading the role definitions again.
 */
window.EOCE = window.EOCE || {};

EOCE.roleCompare = (function () {
    var MAX_ROLES = 6;
    var state = { selected: [], diffOnly: true, actionQ: '' };
    var listeners = [];
    var wired = false;

    function esc(s) { return EOCE.util.escapeHtml(s); }

    // ---- Selection (shared with the Roles table's checkbox column) -----------
    function rows() { return (EOCE.views.roles && EOCE.views.roles.all) || []; }

    function keyOf(r) { return r.sysKey + ':' + r.id; }

    function byKey(key) {
        var found = null;
        rows().forEach(function (r) { if (keyOf(r) === key) found = r; });
        return found;
    }

    function isSelected(key) { return state.selected.indexOf(key) !== -1; }
    function selectedCount() { return state.selected.length; }
    function maxRoles() { return MAX_ROLES; }

    function notify() { listeners.forEach(function (fn) { fn(); }); }
    function onChange(fn) { listeners.push(fn); }

    // Returns true when the selection actually changed (false when adding
    // while already full, so callers - e.g. a checkbox - can revert the UI).
    function setSelected(key, want) {
        var has = isSelected(key);
        if (want === has) return true;
        if (want) {
            if (state.selected.length >= MAX_ROLES) return false;
            state.selected.push(key);
        } else {
            state.selected = state.selected.filter(function (k) { return k !== key; });
        }
        notify();
        if (isOpen()) render();
        return true;
    }

    function toggle(key) { return setSelected(key, !isSelected(key)); }

    function clearAll() {
        state.selected = [];
        notify();
        if (isOpen()) render();
    }

    function selectedRoles() {
        return state.selected.map(byKey).filter(Boolean);
    }

    // ---- Modal chrome ----------------------------------------------------------
    function modalEl() { return document.getElementById('cmpModal'); }
    function backdropEl() { return document.getElementById('cmpBackdrop'); }
    function isOpen() { var m = modalEl(); return !!m && m.classList.contains('open'); }

    function updateHash() {
        var hash = state.selected.length
            ? '#rolecompare' + state.selected.map(function (k) { return '/' + encodeURIComponent(k); }).join('')
            : '#roles';
        // replaceState keeps the deep link current without re-triggering the router.
        history.replaceState(null, '', hash);
    }

    function wire() {
        if (wired) return;
        wired = true;
        var closeBtn = document.getElementById('cmpClose');
        if (closeBtn) closeBtn.addEventListener('click', close);
        var bd = backdropEl();
        if (bd) bd.addEventListener('click', close);
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && isOpen()) close();
        });
    }

    // keys: role keys to ADD to the current selection (does not replace an
    // existing selection) so "compare with another role" from a role's
    // details drawer keeps whatever was already picked in the table.
    function open(keys) {
        wire();
        (keys || []).forEach(function (k) {
            if (byKey(k)) setSelected(k, true);
        });
        var m = modalEl(), bd = backdropEl();
        if (!m || !bd) return;
        m.classList.add('open');
        bd.classList.add('open');
        EOCE.a11y.openDialog(m, document.getElementById('cmpClose'));
        updateHash();
        render();
    }

    function close() {
        var m = modalEl(), bd = backdropEl();
        var wasOpen = isOpen();
        if (m) m.classList.remove('open');
        if (bd) bd.classList.remove('open');
        if (wasOpen) EOCE.a11y.closeDialog(m);
        if ((location.hash || '').indexOf('#rolecompare') === 0) history.replaceState(null, '', '#roles');
    }

    // ---- Review list import ---------------------------------------------------
    // Resolve starred Review-list roles against the currently loaded Roles table
    // rows: match on role name plus - when it resolves - the RBAC system (the
    // item's system may be a key like "EntraID" or a short label like "Entra ID").
    function reviewCandidates() {
        if (!window.EOReview) return [];
        var selected = Object.create(null);
        state.selected.forEach(function (k) { selected[k] = true; });
        var seen = {};
        var out = [];
        EOReview.all().forEach(function (item) {
            if (item.kind !== 'Role' || !item.name) return;
            var nameLc = String(item.name).toLowerCase();
            var sysLc = String(item.system || '').toLowerCase().replace(/\s+/g, '');
            var matches = rows().filter(function (r) {
                if (r.name.toLowerCase() !== nameLc) return false;
                if (!sysLc) return true;
                var sys = EOCE.RBAC_SYSTEMS[r.sysKey];
                return r.sysKey.toLowerCase() === sysLc ||
                    (sys && sys.short.toLowerCase().replace(/\s+/g, '') === sysLc);
            });
            if (!matches.length) {
                matches = rows().filter(function (r) { return r.name.toLowerCase() === nameLc; });
                if (matches.length !== 1) matches = [];
            }
            matches.forEach(function (r) {
                var key = keyOf(r);
                if (selected[key] || seen[key]) return;
                seen[key] = true;
                out.push({ role: r, item: item });
            });
        });
        return out;
    }

    // ---- Rendering ---------------------------------------------------------------
    function actionIndex(role) {
        var idx = {};
        EOCE.rolePerms(role.raw).forEach(function (p) {
            if (p && p.AuthorizedResourceAction) idx[String(p.AuthorizedResourceAction).toLowerCase()] = p;
        });
        return idx;
    }

    function shortName(name) {
        return name.length > 24 ? name.slice(0, 23) + '\u2026' : name;
    }

    function render() {
        var body = document.getElementById('cmpBody');
        if (!body) return;
        var roles = selectedRoles();

        var html = '<div class="cmp-roles-row">';
        roles.forEach(function (r) {
            var sys = EOCE.RBAC_SYSTEMS[r.sysKey];
            html += '<div class="cmp-role-card">' +
                '<div class="cmp-role-card-name">' +
                '<a class="inline-link cell-strong" href="#roles/' + encodeURIComponent(r.sysKey) + '/' + encodeURIComponent(r.id) + '" title="Open role details">' + esc(r.name) + '</a>' +
                '<button type="button" class="chip-x" data-cmp-remove="' + esc(keyOf(r)) + '" aria-label="Remove ' + esc(r.name) + ' from comparison">&#10005;</button></div>' +
                '<div class="cmp-role-card-meta">' + EOCE.util.tierBadge(r.classification) + ' <span class="muted">' + esc(sys.short) + '</span>' +
                (r.isPrivileged ? '<span class="chip priv">privileged</span>' : '') + '</div></div>';
        });
        var candidates = reviewCandidates();
        if (candidates.length && roles.length < MAX_ROLES) {
            html += '<div class="cmp-role-card cmp-role-card-add"><div class="cmp-role-card-meta muted">&#9733; Add from Review list:</div>';
            candidates.slice(0, 6).forEach(function (c) {
                var sys = EOCE.RBAC_SYSTEMS[c.role.sysKey];
                html += '<button type="button" class="chip cmp-add-chip" data-cmp-add="' + esc(keyOf(c.role)) + '">+ ' + esc(c.role.name) + ' <span class="muted">(' + esc(sys.short) + ')</span></button>';
            });
            html += '</div>';
        }
        html += '</div>';

        if (roles.length < 2) {
            html += '<div class="empty" style="padding:32px;"><div class="big">&#8644;</div>' +
                'Check &#8644; boxes for at least two roles in the Roles table to compare their classification, flags and role actions.</div>';
            body.innerHTML = html;
            wireRemoveAdd(body);
            return;
        }

        var indexes = roles.map(actionIndex);
        var union = {};
        roles.forEach(function (r, i) {
            Object.keys(indexes[i]).forEach(function (k) {
                if (!union[k]) union[k] = { perm: indexes[i][k], have: [] };
                union[k].have[i] = true;
                var cur = EOCE.TIER_ORDER.indexOf(union[k].perm.EAMTierLevelName);
                var neu = EOCE.TIER_ORDER.indexOf(indexes[i][k].EAMTierLevelName);
                if (neu !== -1 && (cur === -1 || neu < cur)) union[k].perm = indexes[i][k];
            });
        });
        var actionKeys = Object.keys(union);
        var commonCount = 0, diffCount = 0;
        actionKeys.forEach(function (k) {
            var have = union[k].have, n = 0;
            roles.forEach(function (_, i) { if (have[i]) n++; });
            union[k].isCommon = n === roles.length;
            if (union[k].isCommon) commonCount++; else diffCount++;
        });

        var stats = roles.map(function (r, i) {
            var tiers = { ControlPlane: 0, ManagementPlane: 0, UserAccess: 0, Unclassified: 0 };
            EOCE.rolePerms(r.raw).forEach(function (p) {
                var t = EOCE.TIERS[p.EAMTierLevelName] ? p.EAMTierLevelName : 'Unclassified';
                tiers[t]++;
            });
            var unique = 0;
            actionKeys.forEach(function (k) {
                if (!union[k].have[i]) return;
                var only = true;
                roles.forEach(function (_, j) { if (j !== i && union[k].have[j]) only = false; });
                if (only) unique++;
            });
            return { tiers: tiers, unique: unique, actionCount: EOCE.rolePerms(r.raw).length };
        });

        function cellsOf(fn, format) {
            var vals = roles.map(fn);
            var differs = vals.some(function (v) { return String(v) !== String(vals[0]); });
            var cells = vals.map(function (v) { return '<td>' + (format ? format(v) : esc(String(v))) + '</td>'; });
            return { cells: cells, differs: differs };
        }
        function row(label, cells, differs, titleAttr) {
            return '<tr class="' + (differs ? 'cmp-diff-row' : '') + '"' + (titleAttr ? ' title="' + esc(titleAttr) + '"' : '') + '>' +
                '<td class="cmp-prop">' + label + (differs ? ' <span class="chip cmp-diff-chip" title="Values differ between the selected roles">diff</span>' : '') + '</td>' +
                cells.join('') + '</tr>';
        }

        var anyCustom = roles.some(function (r) { return r.raw.IsCustom !== undefined; });
        var anyCats = roles.some(function (r) { return !!r.raw.Categories; });

        var tierC = cellsOf(function (r) { return r.classification; }, function (v) { return EOCE.util.tierBadge(v); });
        var privC = cellsOf(function (r) { return r.isPrivileged; }, function (v) { return v ? '<span class="chip priv">privileged</span>' : '<span class="muted">&mdash;</span>'; });
        var sysC = cellsOf(function (r) { return EOCE.RBAC_SYSTEMS[r.sysKey].short; });
        var cntC = cellsOf(function (r) { return EOCE.rolePerms(r.raw).length; }, function (v) { return '<span class="cell-strong">' + EOCE.util.formatNumber(v) + '</span>'; });
        var uniqC = {
            cells: stats.map(function (s) { return '<td>' + (s.unique ? '<span class="chip warn">' + EOCE.util.formatNumber(s.unique) + ' unique</span>' : '<span class="muted">0</span>') + '</td>'; }),
            differs: stats.some(function (s) { return s.unique !== stats[0].unique; })
        };

        html += '<table class="grid-table cmp-table cmp-stats-table"><thead><tr><th style="min-width:170px;">Property</th>';
        roles.forEach(function (r) { html += '<th>' + esc(r.name) + '</th>'; });
        html += '</tr></thead><tbody>';
        html += row('Access level (EntraOps)', tierC.cells, tierC.differs);
        html += row('Microsoft isPrivileged flag', privC.cells, privC.differs, 'The PRIVILEGED label assigned by Microsoft to roles/actions that can lead to elevation of privilege');
        html += row('RBAC system', sysC.cells, sysC.differs);
        if (anyCustom) {
            var custC = cellsOf(function (r) { return r.raw.IsCustom === true; }, function (v) { return v ? '<span class="chip">custom</span>' : 'Built-in'; });
            html += row('Role type', custC.cells, custC.differs);
        }
        if (anyCats) {
            var catC = cellsOf(function (r) { return r.raw.Categories || '\u2014'; });
            html += row('Categories', catC.cells, catC.differs);
        }
        html += row('Role actions (total)', cntC.cells, cntC.differs);
        EOCE.TIER_ORDER.forEach(function (t) {
            var vals = stats.map(function (s) { return s.tiers[t]; });
            if (!vals.some(function (v) { return v > 0; })) return;
            var differs = vals.some(function (v) { return v !== vals[0]; });
            var cells = vals.map(function (v) {
                return '<td>' + (v ? '<span class="cell-strong" style="color:' + EOCE.tier(t).color + ';">' + EOCE.util.formatNumber(v) + '</span>' : '<span class="muted">0</span>') + '</td>';
            });
            html += row(EOCE.util.tierBadge(t, { short: true }) + ' actions', cells, differs);
        });
        html += row('Unique actions (not in any other selected role)', uniqC.cells, uniqC.differs);
        html += '</tbody></table>';

        html += '<div class="section-title" style="margin-top:18px;">Role actions' +
            ' <span class="chip brand">' + EOCE.util.formatNumber(commonCount) + ' common</span>' +
            ' <span class="chip ' + (diffCount ? 'warn' : '') + '">' + EOCE.util.formatNumber(diffCount) + ' different</span></div>' +
            '<div class="toolbar" style="margin:8px 0;">' +
            '<div class="search" style="max-width:340px;"><span class="search-ico">&#128269;</span>' +
            '<input type="text" id="cmpActionSearch" placeholder="Filter role actions&hellip;" value="' + esc(state.actionQ) + '"/></div>' +
            '<label class="chip" style="cursor:pointer;gap:6px;"><input type="checkbox" id="cmpDiffOnly" ' + (state.diffOnly ? 'checked' : '') + '/> Differences only</label>' +
            '<span class="muted" id="cmpActionCount" style="font-size:12.5px;"></span></div>' +
            '<div class="cmp-matrix-wrap" id="cmpActionMatrix"></div>';

        body.innerHTML = html;
        wireRemoveAdd(body);
        var searchEl = document.getElementById('cmpActionSearch');
        if (searchEl) searchEl.addEventListener('input', EOCE.util.debounce(function (e) {
            state.actionQ = e.target.value.trim().toLowerCase();
            renderMatrix(roles, union, actionKeys);
        }, 150));
        var diffEl = document.getElementById('cmpDiffOnly');
        if (diffEl) diffEl.addEventListener('change', function (e) {
            state.diffOnly = e.target.checked;
            renderMatrix(roles, union, actionKeys);
        });
        renderMatrix(roles, union, actionKeys);
    }

    function wireRemoveAdd(body) {
        body.querySelectorAll('[data-cmp-remove]').forEach(function (x) {
            x.addEventListener('click', function () { setSelected(x.getAttribute('data-cmp-remove'), false); });
        });
        body.querySelectorAll('[data-cmp-add]').forEach(function (b) {
            b.addEventListener('click', function () { setSelected(b.getAttribute('data-cmp-add'), true); });
        });
    }

    function renderMatrix(roles, union, actionKeys) {
        var host = document.getElementById('cmpActionMatrix');
        if (!host) return;
        var q = state.actionQ;
        var keys = actionKeys.filter(function (k) {
            var u = union[k];
            if (state.diffOnly && u.isCommon) return false;
            if (q && (u.perm.AuthorizedResourceAction + ' ' + (u.perm.Category || '')).toLowerCase().indexOf(q) === -1) return false;
            return true;
        });
        keys.sort(function (a, b) {
            var ta = EOCE.TIER_ORDER.indexOf(union[a].perm.EAMTierLevelName);
            var tb = EOCE.TIER_ORDER.indexOf(union[b].perm.EAMTierLevelName);
            if (ta === -1) ta = EOCE.TIER_ORDER.length;
            if (tb === -1) tb = EOCE.TIER_ORDER.length;
            if (ta !== tb) return ta - tb;
            return a < b ? -1 : 1;
        });

        var html = '<table class="grid-table cmp-table"><thead><tr><th>Role action</th><th class="nowrap">Access level</th>';
        roles.forEach(function (r) { html += '<th class="cmp-check-col" title="' + esc(r.name) + '">' + esc(shortName(r.name)) + '</th>'; });
        html += '</tr></thead><tbody>';

        var LIMIT = 500;
        if (!keys.length) {
            html += '<tr><td colspan="' + (roles.length + 2) + '"><div class="empty" style="padding:20px;">' +
                (state.diffOnly ? 'No differing role actions' + (q ? ' match the filter' : '') + ' &mdash; the selected roles share the same action set.' : 'No role actions match the filter.') +
                '</div></td></tr>';
        } else {
            keys.slice(0, LIMIT).forEach(function (k) {
                var u = union[k];
                var tierName = EOCE.TIERS[u.perm.EAMTierLevelName] ? u.perm.EAMTierLevelName : 'Unclassified';
                html += '<tr class="' + (u.isCommon ? '' : 'cmp-diff-row') + '">' +
                    '<td><span class="cell-mono" style="font-size:12px;">' + EOCE.util.highlight(esc(u.perm.AuthorizedResourceAction), q) + '</span>' +
                    (u.perm.Category ? '<div class="a-cat">' + esc(u.perm.Category) + '</div>' : '') + '</td>' +
                    '<td>' + EOCE.util.tierBadge(tierName, { short: true }) + '</td>';
                roles.forEach(function (_, i) {
                    html += '<td class="cmp-check-col">' + (u.have[i]
                        ? '<span class="cmp-yes" title="Included in this role">&#10003;</span>'
                        : '<span class="cmp-no" title="Not included in this role">&mdash;</span>') + '</td>';
                });
                html += '</tr>';
            });
        }
        html += '</tbody></table>';
        host.innerHTML = html;
        var meta = document.getElementById('cmpActionCount');
        if (meta) meta.textContent = EOCE.util.formatNumber(keys.length) + ' action' + (keys.length === 1 ? '' : 's') +
            (keys.length > LIMIT ? ' (showing first ' + LIMIT + ')' : '');
    }

    return {
        MAX_ROLES: MAX_ROLES,
        keyOf: keyOf,
        isSelected: isSelected,
        selectedCount: selectedCount,
        maxRoles: maxRoles,
        toggle: toggle,
        setSelected: setSelected,
        clearAll: clearAll,
        onChange: onChange,
        open: open,
        close: close,
        isOpen: isOpen
    };
})();
