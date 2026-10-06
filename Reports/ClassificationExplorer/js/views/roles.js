/*
 * Roles explorer - browse classified roles across all RBAC systems
 */
window.EOCE = window.EOCE || {};
EOCE.views = EOCE.views || {};

// Human-friendly labels for the EntraOps "AssignmentMode" field (Microsoft Entra
// directory roles / Identity Governance roles): whether a role can be manually
// assigned ("allowed") or is automatically held by every member/guest ("systemAssigned").
var ROLE_ASSIGNMENT_MODE_LABELS = {
    allowed: 'Allowed (assignable)',
    systemAssigned: 'System-assigned'
};

EOCE.views.roles = {
    state: { q: '', sys: 'all', cat: 'all', assignMode: 'all', tiers: {}, privOnly: false, docMismatchOnly: false, overwriteOnly: false, attackPathOnly: false, scopeAwareOnly: false, learnOnly: false, sortKey: 'name', sortDir: 1 },

    render: function (el, params) {
        var self = this;
        EOCE.TIER_ORDER.forEach(function (t) { if (self.state.tiers[t] === undefined) self.state.tiers[t] = true; });
        if (params && params[0] && EOCE.RBAC_SYSTEMS[params[0]] && EOCE.RBAC_SYSTEMS[params[0]].kind === 'roles') this.state.sys = params[0];

        var sysKeys = EOCE.rolesSystemKeys();
        var rolePaths = sysKeys.map(function (k) { return EOCE.RBAC_SYSTEMS[k].file; });
        var docsKeys = Object.keys(EOCE.DOCS_COMPARE);
        var docsPaths = docsKeys.map(function (k) { return EOCE.DOCS_COMPARE[k].file; });
        return Promise.all([
            EOCE.data.loadAll(rolePaths),
            EOCE.data.load(EOCE.OVERWRITES_FILE),
            EOCE.data.loadAll(docsPaths),
            EOCE.loadScopeAwareActions(),
            EOCE.util.ensureAttackPaths()
        ]).then(function (res) {
            self.docsIndex = {};
            docsKeys.forEach(function (k, i) { self.docsIndex[k] = EOCE.buildDocsIndex(res[2][i]); });
            var scopeAwareActions = res[3];
            self.scopeAwareActionsBySystem = scopeAwareActions;

            var all = [];
            sysKeys.forEach(function (k, i) {
                res[0][i].forEach(function (r) {
                    var catSet = {};
                    var actionNames = [];
                    EOCE.rolePerms(r).forEach(function (p) {
                        if (p.Category) catSet[p.Category] = true;
                        if (p.AuthorizedResourceAction) actionNames.push({ action: p.AuthorizedResourceAction, actionType: p.ActionType });
                    });
                    all.push({
                        sysKey: k,
                        id: r.RoleId,
                        name: r.RoleName,
                        isPrivileged: r.isPrivileged === true,
                        classification: (r.Classification && r.Classification.EAMTierLevelName) || 'Unclassified',
                        actionCount: EOCE.rolePerms(r).length,
                        cats: Object.keys(catSet),
                        attackPaths: EOCE.attackPathsForRole(k, r),
                        docDiff: EOCE.roleDocDiff(k, r, self.docsIndex[k]),
                        scopeAware: EOCE.roleIsScopeAware(k, actionNames, scopeAwareActions),
                        raw: r
                    });
                });
            });

            // Roles that exist ONLY in the Microsoft Learn permissions reference
            // (documented on Learn but not returned by Microsoft Graph). Their tier
            // classification comes from the docs-based classification file
            // (Classification_EntraIdDirectoryRolesFromMsftDocs.json, classified with
            // the same EntraOps role-action rules) - included via the
            // "Include Microsoft Learn-only" toolbar filter.
            docsKeys.forEach(function (k, i) {
                var liveIds = {};
                all.forEach(function (r) { if (r.sysKey === k) liveIds[r.id] = true; });
                (res[2][i] || []).forEach(function (r) {
                    if (!r || !r.RoleId || liveIds[r.RoleId]) return;
                    var catSet = {};
                    var actionNames = [];
                    EOCE.rolePerms(r).forEach(function (p) {
                        if (p.Category) catSet[p.Category] = true;
                        if (p.AuthorizedResourceAction) actionNames.push({ action: p.AuthorizedResourceAction, actionType: p.ActionType });
                    });
                    all.push({
                        sysKey: k,
                        id: r.RoleId,
                        name: r.RoleName,
                        isPrivileged: r.isPrivileged === true,
                        classification: (r.Classification && r.Classification.EAMTierLevelName) || 'Unclassified',
                        actionCount: EOCE.rolePerms(r).length,
                        cats: Object.keys(catSet),
                        attackPaths: EOCE.attackPathsForRole(k, r),
                        docDiff: null,
                        scopeAware: EOCE.roleIsScopeAware(k, actionNames, scopeAwareActions),
                        learnOnly: true,
                        raw: r
                    });
                });
            });

            var overwriteIndex = EOCE.indexRoleOverwrites(res[1]);
            all.forEach(function (r) {
                var o = overwriteIndex[r.sysKey + '|' + r.id];
                if (!o) return;
                r.overwriteInfo = EOCE.roleOverwriteInfo(o, EOCE.rolePerms(r.raw), r.classification);
                // The overwrite tier wins even when the exported role classification disagrees.
                r.classification = r.overwriteInfo.effectiveTier;
            });
            self.all = all;

            el.innerHTML =
                '<div class="view">' +
                '<div class="page-head"><h1>Roles</h1>' +
                '<p>Browse every classified role across Microsoft Entra ID, Azure and Intune. A role\'s access level is the highest-privilege plane among its role actions. Select a role to inspect each action and understand why it lands where it does.</p></div>' +
                '<div id="rolesToolbar"></div>' +
                '<div id="rolesScopeNote"></div>' +
                '<div id="rolesCompareBar"></div>' +
                '<div class="table-wrap"><table class="grid-table" id="rolesTable"></table></div>' +
                '<div class="pager" id="rolesPager"></div>' +
                '</div>';

            self.renderToolbar();
            self.renderTable();
            if (window.EOCE.roleCompare && !self._compareSubscribed) {
                self._compareSubscribed = true;
                EOCE.roleCompare.onChange(function () { self.renderCompareBar(); });
            }

            if (params && params[1]) {
                var match = all.filter(function (r) { return r.id === params[1]; })[0];
                if (match) self.openRole(match);
            }
        });
    },

    renderToolbar: function () {
        var self = this;
        var sysKeys = EOCE.rolesSystemKeys();
        var html = '<div class="toolbar">';
        html += '<div class="search"><span class="search-ico">&#128269;</span>' +
            '<input id="rolesSearch" type="text" placeholder="Search roles by name or description&hellip;" value="' + EOCE.util.escapeHtml(this.state.q) + '"></div>';

        html += '<div class="seg-group" id="sysSeg"><button class="seg' + (this.state.sys === 'all' ? ' active' : '') + '" data-sys="all">All</button>';
        sysKeys.forEach(function (k) {
            html += '<button class="seg' + (self.state.sys === k ? ' active' : '') + '" data-sys="' + k + '">' + EOCE.util.escapeHtml(EOCE.RBAC_SYSTEMS[k].short) + '</button>';
        });
        html += '</div>';

        var cats = this.categoriesFor(this.state.sys);
        if (this.state.cat !== 'all' && cats.indexOf(this.state.cat) === -1) this.state.cat = 'all';
        html += '<select class="filter" id="rolesCat" title="Filter by classification category"><option value="all">All categories (' + cats.length + ')</option>';
        cats.forEach(function (c) {
            html += '<option value="' + EOCE.util.escapeHtml(c) + '"' + (self.state.cat === c ? ' selected' : '') + '>' + EOCE.util.escapeHtml(c) + '</option>';
        });
        html += '</select>';

        var assignModes = this.assignModesFor(this.state.sys);
        if (this.state.assignMode !== 'all' && assignModes.indexOf(this.state.assignMode) === -1) this.state.assignMode = 'all';
        if (assignModes.length) {
            html += '<select class="filter" id="rolesAssignMode" title="Filter by how the role can be assigned (EntraOps AssignmentMode)"><option value="all">All assignment modes</option>';
            assignModes.forEach(function (m) {
                html += '<option value="' + EOCE.util.escapeHtml(m) + '"' + (self.state.assignMode === m ? ' selected' : '') + '>' + EOCE.util.escapeHtml(ROLE_ASSIGNMENT_MODE_LABELS[m] || m) + '</option>';
            });
            html += '</select>';
        }

        html += '<div class="tier-toggles" id="tierToggles">';
        ['ControlPlane', 'ManagementPlane', 'UserAccess', 'Unclassified'].forEach(function (t) {
            html += '<span class="tier-toggle tier-' + t.toLowerCase() + (self.state.tiers[t] ? ' on' : '') + '" data-tier="' + t + '">' +
                '<span class="tier-dot"></span>' + EOCE.tier(t).short + '</span>';
        });
        html += '</div>';

        html += '<label class="chip" style="cursor:pointer;gap:6px;"><input type="checkbox" id="privOnly"' + (this.state.privOnly ? ' checked' : '') + '> Privileged only</label>';
        html += '<label class="chip" style="cursor:pointer;gap:6px;" title="Only roles whose Microsoft Graph definition differs from the Microsoft Learn permissions reference"><input type="checkbox" id="docMismatchOnly"' + (this.state.docMismatchOnly ? ' checked' : '') + '> Doc mismatch</label>';
        if (this.state.sys === 'all' || EOCE.hasDocsCompare(this.state.sys)) {
            html += '<label class="chip" style="cursor:pointer;gap:6px;" title="Include roles that only exist in the Microsoft Learn permissions reference and are not returned by Microsoft Graph"><input type="checkbox" id="rolesLearnOnly"' + (this.state.learnOnly ? ' checked' : '') + '> \u21C4 Include Microsoft Learn-only</label>';
        }
        html += '<label class="chip" style="cursor:pointer;gap:6px;" title="Only roles with an EntraOps role definition overwrite (implicit permissions not visible in their role actions)"><input type="checkbox" id="overwriteOnly"' + (this.state.overwriteOnly ? ' checked' : '') + '> Overwrite</label>';
        html += '<label class="chip" style="cursor:pointer;gap:6px;" title="Only roles referenced in a known documented attack path"><input type="checkbox" id="rolesAttackPathOnly"' + (this.state.attackPathOnly ? ' checked' : '') + '> \u26A0 Attack paths exist</label>';
        html += '<label class="chip" style="cursor:pointer;gap:6px;" title="Only roles whose classification depends on assignment scope \u2014 for example Identity Governance catalog-scoped delegation, or a placeholder-scoped action in Entra ID, Azure, Intune or Defender"><input type="checkbox" id="rolesScopeAwareOnly"' + (this.state.scopeAwareOnly ? ' checked' : '') + '> Scope-aware</label>';
        if (this.state.sys !== 'all') html += EOCE.historyToolbarLink(this.state.sys);
        html += '<span class="toolbar-meta" id="rolesCount"></span>';
        html += '</div>';

        document.getElementById('rolesToolbar').innerHTML = html;

        var note = document.getElementById('rolesScopeNote');
        if (note) note.innerHTML = this.state.sys === 'all' ? '' : EOCE.scopeAwareCallout(this.state.sys);

        document.getElementById('rolesSearch').addEventListener('input', EOCE.util.debounce(function (e) {
            self.state.q = e.target.value.trim(); self.renderTable();
        }, 180));
        document.getElementById('sysSeg').addEventListener('click', function (e) {
            var b = e.target.closest('[data-sys]'); if (!b) return;
            self.state.sys = b.getAttribute('data-sys');
            self.state.cat = 'all';
            self.renderToolbar(); self.renderTable();
        });
        document.getElementById('rolesCat').addEventListener('change', function (e) {
            self.state.cat = e.target.value; self.renderTable();
        });
        var assignModeSel = document.getElementById('rolesAssignMode');
        if (assignModeSel) {
            assignModeSel.addEventListener('change', function (e) {
                self.state.assignMode = e.target.value; self.renderTable();
            });
        }
        document.getElementById('tierToggles').addEventListener('click', function (e) {
            var b = e.target.closest('[data-tier]'); if (!b) return;
            var t = b.getAttribute('data-tier');
            self.state.tiers[t] = !self.state.tiers[t];
            b.classList.toggle('on', self.state.tiers[t]);
            self.renderTable();
        });
        document.getElementById('privOnly').addEventListener('change', function (e) {
            self.state.privOnly = e.target.checked; self.renderTable();
        });
        document.getElementById('docMismatchOnly').addEventListener('change', function (e) {
            self.state.docMismatchOnly = e.target.checked; self.renderTable();
        });
        var learnOnlyToggle = document.getElementById('rolesLearnOnly');
        if (learnOnlyToggle) {
            learnOnlyToggle.addEventListener('change', function (e) {
                self.state.learnOnly = e.target.checked; self.renderTable();
            });
        }
        document.getElementById('overwriteOnly').addEventListener('change', function (e) {
            self.state.overwriteOnly = e.target.checked; self.renderTable();
        });
        document.getElementById('rolesAttackPathOnly').addEventListener('change', function (e) {
            self.state.attackPathOnly = e.target.checked; self.renderTable();
        });
        document.getElementById('rolesScopeAwareOnly').addEventListener('change', function (e) {
            self.state.scopeAwareOnly = e.target.checked; self.renderTable();
        });
    },

    categoriesFor: function (sys) {
        var set = {};
        (this.all || []).forEach(function (r) {
            if (sys !== 'all' && r.sysKey !== sys) return;
            r.cats.forEach(function (c) { set[c] = true; });
        });
        return Object.keys(set).sort(function (x, y) { return x.toLowerCase() < y.toLowerCase() ? -1 : 1; });
    },

    // Distinct EntraOps "AssignmentMode" values present for a system (or across all
    // systems). Most RBAC systems don't carry this field (Azure RBAC, Intune, ...),
    // so the filter is only rendered when at least one role reports a value.
    assignModesFor: function (sys) {
        var set = {};
        (this.all || []).forEach(function (r) {
            if (sys !== 'all' && r.sysKey !== sys) return;
            if (r.raw.AssignmentMode) set[r.raw.AssignmentMode] = true;
        });
        return Object.keys(set).sort();
    },

    filtered: function () {
        var s = this.state;
        var q = s.q.toLowerCase();
        return this.all.filter(function (r) {
            if (r.learnOnly && !s.learnOnly) return false;
            if (s.sys !== 'all' && r.sysKey !== s.sys) return false;
            if (s.cat !== 'all' && r.cats.indexOf(s.cat) === -1) return false;
            if (s.assignMode !== 'all' && (r.raw.AssignmentMode || '') !== s.assignMode) return false;
            if (!s.tiers[r.classification]) return false;
            if (s.privOnly && !r.isPrivileged) return false;
            if (s.docMismatchOnly && EOCE.docMismatchCount(r.docDiff) === 0) return false;
            if (s.overwriteOnly && !r.overwriteInfo) return false;
            if (s.attackPathOnly && (!r.attackPaths || r.attackPaths.length === 0)) return false;
            if (s.scopeAwareOnly && !r.scopeAware) return false;
            if (q) {
                var hay = (r.name + ' ' + (r.raw.RichDescription || '') + ' ' + (r.raw.Categories || '')).toLowerCase();
                if (hay.indexOf(q) === -1) return false;
            }
            return true;
        });
    },

    sortRows: function (rows) {
        var s = this.state, dir = s.sortDir;
        var key = s.sortKey;
        return rows.sort(function (a, b) {
            var va, vb;
            if (key === 'tier') { va = EOCE.tier(a.classification).tag; vb = EOCE.tier(b.classification).tag; }
            else if (key === 'actions') { va = a.actionCount; vb = b.actionCount; }
            else if (key === 'sys') { va = a.sysKey; vb = b.sysKey; }
            else { va = a.name.toLowerCase(); vb = b.name.toLowerCase(); }
            if (va < vb) return -1 * dir;
            if (va > vb) return 1 * dir;
            return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1;
        });
    },

    renderTable: function (keepLimit) {
        var self = this;
        var rows = this.sortRows(this.filtered());
        var s = this.state;
        if (!keepLimit) this._visibleRows = 100;
        var visibleRows = Math.min(this._visibleRows || 100, rows.length);
        var cmp = window.EOCE.roleCompare;
        var histStatus = {}; // sysKey -> { id -> 'added'|'changed' }
        function arrow(key) { return s.sortKey === key ? '<span class="arrow">' + (s.sortDir === 1 ? '\u25B2' : '\u25BC') + '</span>' : '<span class="arrow">\u21C5</span>'; }

        var html = '<thead><tr>' +
            '<th class="no-sort" style="width:28px;" title="Select for comparison">&#8644;</th>' +
            '<th data-sort="name">Role' + arrow('name') + '</th>' +
            '<th data-sort="sys" class="nowrap">System' + arrow('sys') + '</th>' +
            '<th data-sort="tier" class="nowrap">Access level' + arrow('tier') + '</th>' +
            '<th data-sort="actions" class="nowrap" style="text-align:right;">Actions' + arrow('actions') + '</th>' +
            '<th class="no-sort"></th>' +
            '</tr></thead><tbody>';

        if (!rows.length) {
            html += '<tr><td colspan="6"><div class="empty"><div class="big">&#128269;</div>No roles match your filters.</div></td></tr>';
        } else {
            rows.slice(0, visibleRows).forEach(function (r, idx) {
                var sys = EOCE.RBAC_SYSTEMS[r.sysKey];
                var nm = EOCE.util.highlight(EOCE.util.escapeHtml(r.name), s.q);
                var ovr = EOCE.implicitPermissionsChip(r.overwriteInfo);
                var learnChip = r.learnOnly ? '<span class="chip docdiff" title="This role only exists in the Microsoft Learn permissions reference - it is not returned by Microsoft Graph">Learn-only</span>' : '';
                var scopeChip = EOCE.scopeAwareChip(r.sysKey, r.scopeAware);
                var atkChip = EOCE.attackPathChip((r.attackPaths || []).length);
                var docChip = EOCE.docMismatchChip(r.docDiff);
                if (histStatus[r.sysKey] === undefined) histStatus[r.sysKey] = EOCE.historyLatestItemStatus(r.sysKey) || {};
                var histChip = EOCE.historyChangedChip(histStatus[r.sysKey][r.id]);
                var key = cmp ? cmp.keyOf(r) : '';
                var checked = cmp && cmp.isSelected(key);
                html += '<tr data-idx="' + idx + '"' + (checked ? ' class="cmp-row"' : '') + '>' +
                    '<td><input type="checkbox" data-cmp="' + idx + '" title="Select for comparison" ' + (checked ? 'checked' : '') + '/></td>' +
                    '<td><span class="cell-strong">' + nm + '</span> ' + (r.isPrivileged ? '<span class="chip priv">privileged</span> ' : '') + (learnChip ? learnChip + ' ' : '') + scopeChip + (scopeChip ? ' ' : '') + atkChip + (atkChip ? ' ' : '') + docChip + (docChip ? ' ' : '') + (histChip ? histChip + ' ' : '') + ovr + '</td>' +
                    '<td class="muted nowrap">' + EOCE.util.escapeHtml(sys.short) + '</td>' +
                    '<td>' + EOCE.util.tierBadge(r.classification) + '</td>' +
                    '<td class="muted nowrap" style="text-align:right;">' + EOCE.util.formatNumber(r.actionCount) + '</td>' +
                    '<td class="muted nowrap" style="text-align:right;">Details &#8250;</td>' +
                    '</tr>';
            });
        }
        html += '</tbody>';

        var table = document.getElementById('rolesTable');
        table.innerHTML = html;
        self._rows = rows;

        table.querySelectorAll('thead th[data-sort]').forEach(function (th) {
            th.addEventListener('click', function () {
                var key = th.getAttribute('data-sort');
                if (s.sortKey === key) s.sortDir *= -1; else { s.sortKey = key; s.sortDir = 1; }
                self.renderTable();
            });
        });
        table.querySelectorAll('tbody tr[data-idx]').forEach(function (tr) {
            tr.addEventListener('click', function (ev) {
                if (ev.target.closest('[data-cmp]')) return;
                self.openRole(rows[parseInt(tr.getAttribute('data-idx'), 10)]);
            });
        });
        table.querySelectorAll('input[data-cmp]').forEach(function (cb) {
            cb.addEventListener('change', function (ev) {
                ev.stopPropagation();
                var r = rows[parseInt(cb.dataset.cmp, 10)];
                var key = cmp.keyOf(r);
                var ok = cmp.setSelected(key, cb.checked);
                if (!ok) {
                    cb.checked = false;
                    return;
                }
                cb.closest('tr').classList.toggle('cmp-row', cb.checked);
            });
        });

        document.getElementById('rolesCount').textContent =
            EOCE.util.formatNumber(rows.length) + ' role' + (rows.length === 1 ? '' : 's');
        var pager = document.getElementById('rolesPager');
        pager.innerHTML = visibleRows < rows.length
            ? 'Showing ' + EOCE.util.formatNumber(visibleRows) + ' of ' + EOCE.util.formatNumber(rows.length) + ' roles. <button type="button" class="btn" data-show-more>Show 100 more</button>'
            : '';
        var more = pager.querySelector('[data-show-more]');
        if (more) more.addEventListener('click', function () {
            self._visibleRows = visibleRows + 100;
            self.renderTable(true);
        });
        this.renderCompareBar();
    },

    renderCompareBar: function () {
        var host = document.getElementById('rolesCompareBar');
        if (!host) return;
        var cmp = window.EOCE.roleCompare;
        if (!cmp) { host.innerHTML = ''; return; }
        var n = cmp.selectedCount();
        if (n < 1) { host.innerHTML = ''; return; }
        host.innerHTML =
            '<div class="cmp-bar">' +
            '<span class="chip warn">' + n + '/' + cmp.maxRoles() + ' selected</span>' +
            (n >= 2
                ? '<button type="button" class="btn small primary" id="rolesCompareBtn">&#8644; Compare selected (' + n + ')</button>'
                : '<span class="muted" style="font-size:12.5px;">Select one more role to compare</span>') +
            '<button type="button" class="btn small" id="rolesCompareClear">Clear selection</button>' +
            '</div>';
        var btn = document.getElementById('rolesCompareBtn');
        if (btn) btn.addEventListener('click', function () { cmp.open([]); });
        document.getElementById('rolesCompareClear').addEventListener('click', function () {
            cmp.clearAll();
            document.querySelectorAll('#rolesTable input[data-cmp]:checked').forEach(function (cb) {
                cb.checked = false;
                cb.closest('tr').classList.remove('cmp-row');
            });
        });
    },

    openRole: function (r) {
        var self = this;
        var sys = EOCE.RBAC_SYSTEMS[r.sysKey];
        var raw = r.raw;
        var perms = EOCE.rolePerms(raw).slice();

        // group by tier
        var groups = { ControlPlane: [], ManagementPlane: [], UserAccess: [], Unclassified: [] };
        perms.forEach(function (p) {
            var key = EOCE.TIERS[p.EAMTierLevelName] ? p.EAMTierLevelName : 'Unclassified';
            groups[key].push(p);
        });

        var dist = EOCE.charts.emptyDist();
        perms.forEach(function (p) { EOCE.charts.addToDist(dist, p.EAMTierLevelName); });

        // Only offer the Actions / Data actions plane filter when this role actually
        // mixes both (most systems have no ActionType at all, or are Actions-only).
        var hasAction = perms.some(function (p) { return self.planeOf(p) === 'Action'; });
        var hasDataAction = perms.some(function (p) { return self.planeOf(p) === 'DataAction'; });
        var showsPlaneFilter = hasAction && hasDataAction;

        var body = '';
        body += '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px;">' +
            EOCE.util.tierBadge(r.classification) +
            '<span class="chip brand">' + EOCE.util.escapeHtml(sys.short) + '</span>' +
            (r.isPrivileged ? '<span class="chip priv">privileged</span>' : '') +
            (raw.IsCustom === true ? '<span class="chip">custom</span>' : '') +
            (r.learnOnly ? '<span class="chip docdiff" title="This role only exists in the Microsoft Learn permissions reference - it is not returned by Microsoft Graph">Learn-only</span>' : '') +
            EOCE.scopeAwareChip(r.sysKey, r.scopeAware) +
            EOCE.implicitPermissionsChip(r.overwriteInfo) +
            EOCE.attackPathChip((r.attackPaths || []).length) +
            EOCE.docMismatchChip(r.docDiff) +
            (window.EOReview ? '<button type="button" id="eoRoleStar" class="eo-star" title="Add to review list">&#9734;</button>' : '') +
            '</div>';

        if (!r.learnOnly) {
            body += '<div style="margin:0 0 14px;display:flex;gap:16px;flex-wrap:wrap;"><a class="inline-link" href="#overview/role/' +
                encodeURIComponent(r.sysKey) + '/' + encodeURIComponent(r.id) + '">&#8862; View in EAM Map &rarr;</a>' +
                '<a class="inline-link" href="#" id="drawerCompareLink">&#8644; Compare with another role &rarr;</a>' +
                EOCE.historyItemLink(r.sysKey, r.name) + '</div>';
        }

        var t = EOCE.tier(r.classification);
        var ovrInfo = r.overwriteInfo;
        if (ovrInfo) {
            var ovr = ovrInfo.overwrite;
            body += '<div class="callout ' + (r.classification === 'ControlPlane' ? 'control' : 'implicit') + '">' +
                '<div class="callout-title">Why ' + EOCE.util.escapeHtml(t.label) + '? &middot; implicit permissions</div>' +
                'This role is pinned to <strong>' + EOCE.util.escapeHtml(t.label) + '</strong>' +
                (ovr.Service ? ' (' + EOCE.util.escapeHtml(ovr.Service) + ')' : '') +
                ' by a role definition overwrite, independently of its listed role actions. ' +
                (ovrInfo.actionCount
                    ? 'Its ' + EOCE.util.formatNumber(ovrInfo.actionCount) + ' listed role action' + (ovrInfo.actionCount === 1 ? ' alone reaches ' : 's alone reach ') + EOCE.util.tierBadge(ovrInfo.actionTier, { short: true }) + '.'
                    : 'It has no listed role actions.') +
                '<div style="margin-top:8px;"><em>' + EOCE.util.escapeHtml(ovr.Justification || '') + '</em></div>' +
                (ovrInfo.exportedMismatch
                    ? '<div class="muted" style="margin-top:8px;font-size:12px;">Note: the exported classification data reports ' + EOCE.util.tierBadge(ovrInfo.exportedTier, { short: true }) +
                    ' for this role; the explorer shows the overwrite tier instead.</div>'
                    : '') +
                '</div>';
        } else {
            body += '<div class="callout ' + (r.classification === 'ControlPlane' ? 'control' : '') + '">' +
                '<div class="callout-title">Why ' + EOCE.util.escapeHtml(t.label) + '?</div>' +
                'This role is classified as <strong>' + EOCE.util.escapeHtml(t.label) + '</strong> because it is the highest-privilege plane among its ' +
                EOCE.util.formatNumber(perms.length) + ' role action' + (perms.length === 1 ? '' : 's') + '. ' +
                EOCE.util.escapeHtml(t.description) + '</div>';
        }

        if (r.scopeAware) {
            body += EOCE.scopeAwareCallout(r.sysKey);
            // Attribution: WHICH of this role's own actions actually triggered the scope-aware
            // flag - a role can be flagged because of a single unrelated action (e.g. Key Vault
            // Data Access Administrator is scope-aware via Microsoft.Authorization/roleAssignments/
            // write, not its Key Vault secrets/keys access), so don't leave it as a blanket claim.
            var actionEntries = perms.map(function (p) { return { action: p.AuthorizedResourceAction, actionType: p.ActionType }; });
            var scopeAwareMatches = EOCE.scopeAwareMatchesForRole(r.sysKey, actionEntries, self.scopeAwareActionsBySystem);
            if (scopeAwareMatches.length) {
                body += '<div class="callout scope" style="margin-top:-4px;"><div class="callout-title">Scope-aware because of</div>' +
                    'This role’s classification depends on scope specifically because it grants:' +
                    '<ul style="margin:8px 0 0;padding-left:18px;">' +
                    scopeAwareMatches.slice(0, 8).map(function (a) { return '<li class="cell-mono" style="font-size:12px;">' + EOCE.util.escapeHtml(a) + '</li>'; }).join('') +
                    '</ul>' +
                    (scopeAwareMatches.length > 8 ? '<div class="muted" style="margin-top:4px;font-size:12px;">+' + (scopeAwareMatches.length - 8) + ' more</div>' : '') +
                    '</div>';
            }
        }

        if (r.learnOnly) {
            var docsCfg = EOCE.DOCS_COMPARE[r.sysKey] || {};
            body += '<div class="callout scope"><div class="callout-title">\u21C4 Only in ' + EOCE.util.escapeHtml(docsCfg.docsLabel || 'Microsoft Learn') + '</div>' +
                'This role is documented in the Microsoft Learn permissions reference but was not returned by Microsoft Graph. ' +
                'Its access level was classified from the documented role actions with the same EntraOps classification rules used for live role definitions.</div>';
        }

        body += EOCE.attackPathCallout(r.attackPaths);
        body += EOCE.docMismatchCallout(r.sysKey, r.docDiff);

        // InheritsPermissionsFrom holds role IDs (GUIDs) of other roles in the same
        // system whose permissions this role inherits (for example the built-in
        // "Directory Readers" baseline). Resolve each ID to its role name within the
        // same system and, when found, render it as a link that jumps to that role's
        // own details rather than showing the raw GUID.
        var inheritsHtml = '';
        if (raw.InheritsPermissionsFrom && raw.InheritsPermissionsFrom.length) {
            inheritsHtml = raw.InheritsPermissionsFrom.map(function (pid) {
                var match = (self.all || []).filter(function (x) { return x.sysKey === r.sysKey && x.id === pid; })[0];
                if (match) {
                    return '<a href="#" class="inline-link inherit-role-link" data-role-id="' + EOCE.util.escapeHtml(pid) + '">' +
                        EOCE.util.escapeHtml(match.name) + '</a>';
                }
                return '<span class="cell-mono">' + EOCE.util.escapeHtml(pid) + '</span>';
            }).join(', ');
        }

        body += '<dl class="kv">' +
            '<dt>Role ID</dt><dd class="cell-mono">' + EOCE.util.escapeHtml(r.id || '—') + '</dd>' +
            '<dt>System</dt><dd>' + EOCE.util.escapeHtml(sys.name) + '</dd>' +
            (raw.Categories ? '<dt>Categories</dt><dd>' + EOCE.util.escapeHtml(raw.Categories) + '</dd>' : '') +
            (raw.AssignmentMode ? '<dt>Assignment mode</dt><dd title="EntraOps AssignmentMode: whether this role can be manually assigned or is automatically held (e.g. by every user/guest)">' +
                EOCE.util.escapeHtml(ROLE_ASSIGNMENT_MODE_LABELS[raw.AssignmentMode] || raw.AssignmentMode) + '</dd>' : '') +
            (inheritsHtml ? '<dt>Inherits permissions from</dt><dd>' + inheritsHtml + '</dd>' : '') +
            '<dt>Role actions</dt><dd>' + EOCE.util.formatNumber(perms.length) + '</dd>' +
            '</dl>';

        if (perms.length) {
            body += '<div style="margin:10px 0 16px;">' + EOCE.charts.distBar(dist) + EOCE.charts.distLegend(dist) + '</div>';
        }

        if (raw.RichDescription) {
            body += '<div class="section-title">Description</div><div class="rich-desc">' + EOCE.util.escapeHtml(raw.RichDescription) + '</div>';
        }

        body += '<div class="section-title">Role actions by access level</div>';
        var docModeOptions = '';
        if (r.docDiff) {
            if (EOCE.docMismatchCount(r.docDiff) > 0) { docModeOptions += '<option value="mismatch">Doc mismatches only</option>'; }
            if (r.docDiff.onlyInGraph && r.docDiff.onlyInGraph.length > 0) { docModeOptions += '<option value="notindocs">Not in docs</option>'; }
            if (r.docDiff.onlyInDocs && r.docDiff.onlyInDocs.length > 0) { docModeOptions += '<option value="notinroledef">Not in role def</option>'; }
        }
        body += '<div class="toolbar" style="margin-bottom:10px;"><div class="search" style="min-width:auto;"><span class="search-ico">&#128269;</span>' +
            '<input id="roleActionFilter" type="text" placeholder="Filter actions\u2026"></div>' +
            '<select class="filter" id="roleActionMode"><option value="all">All actions</option>' +
            '<option value="privileged">IsPrivileged only</option>' + docModeOptions + '</select>' +
            (showsPlaneFilter ? '<select class="filter" id="roleActionPlane" title="Azure RBAC keeps control/management plane Actions and data plane DataActions in separate namespaces \u2014 matches the Actions / Data actions split shown in the Azure Portal and Microsoft Learn"><option value="all">Actions + Data actions</option><option value="action">Actions only</option><option value="dataaction">Data actions only</option></select>' : '') +
            (ovrInfo
                ? '<label class="chip" style="cursor:pointer;gap:6px;" title="Show permissions that are not part of the role definition (role definition overwrite), separated from the listed role actions">' +
                '<input type="checkbox" id="roleImplicitToggle" checked> Include implicit permissions</label>' +
                '<button type="button" class="info-btn" id="roleImplicitInfoBtn" aria-expanded="false" aria-controls="roleImplicitInfo" title="What are implicit permissions?">i</button>'
                : '') +
            '</div>';
        if (ovrInfo) {
            body += '<div class="callout implicit" id="roleImplicitInfo" hidden>' + EOCE.implicitPermissionsInfoHtml() + '</div>';
            body += '<div id="roleImplicitList">' + this.renderImplicitBlock(ovrInfo) + '</div>';
        }
        body += '<div id="roleActionList">' + this.renderActionGroups(groups, '', r.docDiff, r.sysKey, 'all', 'all') + '</div>'
        body += '<div style="margin-top:18px;"><a href="' + sys.docs + '" target="_blank" rel="noopener noreferrer" class="inline-link">' + EOCE.util.escapeHtml(sys.short) + ' permissions reference &#8599;</a></div>';

        EOCE.app.openDrawer(EOCE.util.escapeHtml(sys.short) + ' role', EOCE.util.escapeHtml(r.name), body);

        // Opens the Role Comparison blade directly (no hash navigation needed -
        // the Roles page underneath doesn't need to change) with this role added
        // to whatever is already selected via the table's compare checkboxes.
        var compareLink = document.getElementById('drawerCompareLink');
        if (compareLink && window.EOCE.roleCompare) {
            compareLink.addEventListener('click', function (ev) {
                ev.preventDefault();
                EOCE.app.closeDrawer();
                EOCE.roleCompare.open([EOCE.roleCompare.keyOf(r)]);
            });
        }

        document.querySelectorAll('.inherit-role-link').forEach(function (a) {
            a.addEventListener('click', function (ev) {
                ev.preventDefault();
                var pid = a.getAttribute('data-role-id');
                var match = (self.all || []).filter(function (x) { return x.sysKey === r.sysKey && x.id === pid; })[0];
                if (match) self.openRole(match);
            });
        });

        // Review list star (role incl. its classification scope).
        if (window.EOReview) {
            var starBtn = document.getElementById('eoRoleStar');
            if (starBtn) {
                var reviewId = EOReview.makeId('role', r.sysKey, r.name, 'classification');
                EOReview.updateStar(starBtn, EOReview.has(reviewId));
                starBtn.addEventListener('click', function () {
                    var on = EOReview.toggle({
                        id: reviewId,
                        kind: 'Role',
                        system: sys.short,
                        name: r.name,
                        scope: 'Role classification (tenant-wide)',
                        tier: r.classification,
                        hash: '#roles/' + encodeURIComponent(r.sysKey) + '/' + encodeURIComponent(r.id)
                    });
                    EOReview.updateStar(starBtn, on);
                });
            }
        }

        var actionState = { q: '', mode: 'all', plane: 'all' };
        function rerenderActions() {
            document.getElementById('roleActionList').innerHTML =
                self.renderActionGroups(groups, actionState.q, r.docDiff, r.sysKey, actionState.mode, actionState.plane);
        }
        var fi = document.getElementById('roleActionFilter');
        if (fi) fi.addEventListener('input', EOCE.util.debounce(function (e) {
            actionState.q = e.target.value.trim().toLowerCase(); rerenderActions();
        }, 120));
        var mi = document.getElementById('roleActionMode');
        if (mi) mi.addEventListener('change', function (e) {
            actionState.mode = e.target.value; rerenderActions();
        });
        var pi = document.getElementById('roleActionPlane');
        if (pi) pi.addEventListener('change', function (e) {
            actionState.plane = e.target.value; rerenderActions();
        });
        var implicitToggle = document.getElementById('roleImplicitToggle');
        if (implicitToggle) implicitToggle.addEventListener('change', function (e) {
            document.getElementById('roleImplicitList').hidden = !e.target.checked;
        });
        var implicitInfoBtn = document.getElementById('roleImplicitInfoBtn');
        if (implicitInfoBtn) implicitInfoBtn.addEventListener('click', function () {
            var info = document.getElementById('roleImplicitInfo');
            info.hidden = !info.hidden;
            implicitInfoBtn.setAttribute('aria-expanded', String(!info.hidden));
        });
    },

    // Implicit permissions from a role definition overwrite - rendered in its own block so they
    // are never mixed with the role actions of the role definition.
    renderImplicitBlock: function (info) {
        var o = info.overwrite;
        var t = EOCE.tier(info.effectiveTier);
        return '<div class="implicit-block">' +
            '<div class="group-head">' + EOCE.util.tierBadge(info.effectiveTier) +
            '<span class="chip implicit">\u25C8 implicit permissions</span>' +
            '<span class="g-count">not part of the role definition</span></div>' +
            '<div class="action-row implicit" style="border-left:3px dashed ' + t.color + ';">' +
            '<div style="min-width:0;"><div class="a-name">' + EOCE.util.escapeHtml(o.Service || 'Implicit permissions') + '</div>' +
            '<div class="a-cat">' + EOCE.util.escapeHtml(o.Justification || '') + '</div>' +
            '<div class="a-cat">' + EOCE.util.escapeHtml(EOCE.implicitPermissionsSummary(info)) + '</div>' +
            '<div class="a-cat cell-mono">TaggedBy: RoleDefinitionOverwrites</div>' +
            '</div>' + EOCE.util.tierBadge(info.effectiveTier, { short: true }) + '</div>' +
            '<div class="implicit-sep"><span>Role actions from the role definition</span></div>' +
            '</div>';
    },

    // Azure RBAC keeps control/management plane Actions and data plane DataActions in
    // entirely separate namespaces (see Get-EntraOpsPrivilegedEAMAzure.ps1) - this mirrors
    // Microsoft's own role-definition view (Portal / Learn show "Actions" and "Data Actions"
    // as separate lists), defaulting an absent/unrecognised ActionType to "Action".
    planeOf: function (p) { return p.ActionType === 'DataAction' ? 'DataAction' : 'Action'; },

    // Single action row, shared by the flat and plane-split rendering paths below.
    renderActionRow: function (p, tk, filter, graphOnly) {
        var t = EOCE.tier(tk);
        var name = EOCE.util.highlight(EOCE.util.escapeHtml(p.AuthorizedResourceAction), filter);
        var isGraphOnly = graphOnly[String(p.AuthorizedResourceAction).toLowerCase()] === true;
        var flag = isGraphOnly ? '<span class="a-flag" title="Present in the live Microsoft Graph role definition but not documented in the Microsoft Learn permissions reference">not in docs</span>' : '';
        return '<div class="action-row' + (isGraphOnly ? ' mismatch' : '') + '" style="border-left:3px solid ' + t.color + ';">' +
            '<div style="min-width:0;"><div class="a-name">' + name + flag + '</div>' +
            (p.Category ? '<div class="a-cat">' + EOCE.util.escapeHtml(p.Category) + (p.ActionType ? ' &middot; ' + EOCE.util.escapeHtml(p.ActionType) : '') + '</div>' : '') +
            '</div>' + EOCE.util.tierBadge(tk, { short: true }) + '</div>';
    },

    // mode: 'all' | 'privileged' (ControlPlane only) | 'mismatch' (any doc diff)
    //       'notindocs' (in Graph, absent from MS Learn) | 'notinroledef' (in MS Learn, absent from Graph)
    // planeFilter: 'all' | 'action' (control/management plane only) | 'dataaction' (data plane only)
    renderActionGroups: function (groups, filter, docDiff, sysKey, mode, planeFilter) {
        var self = this;
        var html = '';
        var any = false;
        var graphOnly = (docDiff && docDiff.graphOnlyLower) || {};
        var showTierGroups = mode !== 'notinroledef';
        var showOnlyInDocs = mode === 'all' || mode === 'mismatch' || mode === 'notinroledef';

        if (showTierGroups) {
            EOCE.TIER_ORDER.forEach(function (tk) {
                var list = groups[tk];
                if (!list || !list.length) return;
                if (mode === 'privileged' && tk !== 'ControlPlane') return;
                var shown = list.filter(function (p) {
                    if ((mode === 'mismatch' || mode === 'notindocs') && graphOnly[String(p.AuthorizedResourceAction).toLowerCase()] !== true) return false;
                    if (planeFilter === 'action' && self.planeOf(p) !== 'Action') return false;
                    if (planeFilter === 'dataaction' && self.planeOf(p) !== 'DataAction') return false;
                    if (filter && (p.AuthorizedResourceAction + ' ' + (p.Category || '')).toLowerCase().indexOf(filter) === -1) return false;
                    return true;
                });
                if (!shown.length) return;
                any = true;
                html += '<div class="group-head">' + EOCE.util.tierBadge(tk) + '<span class="g-count">' + shown.length + ' action' + (shown.length === 1 ? '' : 's') + '</span></div>';

                // Only split into "Actions" / "Data actions" sub-groups when this tier
                // actually mixes both planes (most systems have no ActionType at all, or
                // are Actions-only, and get the plain flat list as before).
                var planes = {};
                shown.forEach(function (p) { planes[self.planeOf(p)] = true; });
                if (planes.Action && planes.DataAction) {
                    var actionItems = shown.filter(function (p) { return self.planeOf(p) === 'Action'; });
                    var dataItems = shown.filter(function (p) { return self.planeOf(p) === 'DataAction'; });
                    html += '<div class="group-subhead"><span class="chip">Actions</span><span class="g-count">' + actionItems.length + ' control/management plane action' + (actionItems.length === 1 ? '' : 's') + '</span></div>';
                    actionItems.forEach(function (p) { html += self.renderActionRow(p, tk, filter, graphOnly); });
                    html += '<div class="group-subhead"><span class="chip dataplane" title="Azure RBAC data plane operations - a separate permission namespace from control/management plane Actions, matching how the Azure Portal and Microsoft Learn present role definitions">Data actions</span><span class="g-count">' + dataItems.length + ' data plane action' + (dataItems.length === 1 ? '' : 's') + '</span></div>';
                    dataItems.forEach(function (p) { html += self.renderActionRow(p, tk, filter, graphOnly); });
                } else {
                    shown.forEach(function (p) { html += self.renderActionRow(p, tk, filter, graphOnly); });
                }
            });
        }

        if (showOnlyInDocs) {
            // Actions documented on Microsoft Learn but absent from the live (Graph) definition.
            var onlyInDocs = (docDiff && docDiff.onlyInDocs) || [];
            if (onlyInDocs.length) {
                var cfg = EOCE.DOCS_COMPARE[sysKey] || {};
                var docsLabel = cfg.docsLabel || 'Microsoft Learn';
                var shownDocs = filter ? onlyInDocs.filter(function (a) {
                    return a.toLowerCase().indexOf(filter) !== -1;
                }) : onlyInDocs;
                if (shownDocs.length) {
                    any = true;
                    html += '<div class="group-head"><span class="chip docdiff">\u21C4 only in ' + EOCE.util.escapeHtml(docsLabel) + '</span>' +
                        '<span class="g-count">' + shownDocs.length + ' action' + (shownDocs.length === 1 ? '' : 's') + '</span></div>';
                    shownDocs.forEach(function (a) {
                        var name = EOCE.util.highlight(EOCE.util.escapeHtml(a), filter);
                        html += '<div class="action-row mismatch" style="border-left:3px solid #8764b8;">' +
                            '<div style="min-width:0;"><div class="a-name">' + name +
                            '<span class="a-flag" title="Documented in the ' + EOCE.util.escapeHtml(docsLabel) +
                            ' permissions reference but not present in the live Microsoft Graph role definition">not in definition</span></div>' +
                            '<div class="a-cat">Documented on ' + EOCE.util.escapeHtml(docsLabel) + ', not returned by Microsoft Graph</div>' +
                            '</div></div>';
                    });
                }
            }
        }

        if (!any) {
            var total = 0;
            Object.keys(groups).forEach(function (k) { total += (groups[k] || []).length; });
            html = total || filter || mode !== 'all'
                ? '<div class="empty" style="padding:24px;">No actions match the filter.</div>'
                : '<div class="empty" style="padding:24px;">No role actions are listed in the role definition.</div>';
        }
        return html;
    }
};
