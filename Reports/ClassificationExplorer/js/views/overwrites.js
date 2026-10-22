/*
 * Role Definition Overwrites - roles classified independently of their actions
 */
window.EOCE = window.EOCE || {};
EOCE.views = EOCE.views || {};

EOCE.views.overwrites = {
    sysFor: function (rbac) {
        return EOCE.overwriteSysKey(rbac);
    },

    render: function (el) {
        var self = this;
        return Promise.all([
            EOCE.data.load(EOCE.OVERWRITES_FILE),
            EOCE.data.load(EOCE.RBAC_SYSTEMS.EntraID.file),
            EOCE.data.load(EOCE.RBAC_SYSTEMS.EntraID.definition)
        ]).then(function (res) {
            var overwrites = res[0];
            // Role action lookup by RoleId (Entra ID output).
            var roleById = {};
            res[1].forEach(function (r) { roleById[r.RoleId] = r; });
            // Service -> defining actions (from resolved definition).
            var serviceActions = {};
            res[2].forEach(function (tierObj) {
                (tierObj.TierLevelDefinition || []).forEach(function (def) {
                    if (!def.Service) return;
                    var bucket = serviceActions[def.Service] || (serviceActions[def.Service] = { tier: tierObj.EAMTierLevelName, actions: [] });
                    (def.RoleDefinitionActions || []).forEach(function (a) { if (bucket.actions.indexOf(a) === -1) bucket.actions.push(a); });
                });
            });
            self.roleById = roleById;
            self.serviceActions = serviceActions;
            self.data = overwrites;

            var html = '<div class="view">';
            html += '<div class="page-head"><h1>Role Definition Overwrites</h1>' +
                '<p>Some roles are sensitive for reasons that are <em>not</em> visible in their listed role actions &mdash; they carry implicit powers (for example overwriting synced identities, becoming local admin on devices, or resetting credentials of privileged accounts). EntraOps overrides the classification of these roles explicitly, each with a documented justification.</p></div>';

            html += '<div class="grid cols-4" style="margin-bottom:20px;">';
            var dist = EOCE.charts.emptyDist();
            overwrites.forEach(function (o) { EOCE.charts.addToDist(dist, o.EAMTierLevelName); });
            html += '<div class="stat"><span class="stat-accent" style="background:var(--brand)"></span><div class="stat-label">Total overwrites</div><div class="stat-value">' + overwrites.length + '</div><div class="stat-sub">Manually pinned classifications</div></div>';
            ['ControlPlane', 'ManagementPlane', 'UserAccess'].forEach(function (k) {
                var t = EOCE.tier(k);
                html += '<div class="stat"><span class="stat-accent" style="background:' + t.color + '"></span><div class="stat-label">' + t.label + '</div><div class="stat-value" style="color:' + t.color + '">' + (dist[k] || 0) + '</div><div class="stat-sub">overwritten to Tier ' + t.tag + '</div></div>';
            });
            html += '</div>';

            html += '<div class="table-wrap"><table class="grid-table" id="ovrTable">' +
                '<thead><tr><th>Role</th><th class="nowrap">System</th><th class="nowrap">Service</th><th class="nowrap">Overwritten to</th><th>Justification</th></tr></thead><tbody>';
            overwrites.forEach(function (o, idx) {
                html += '<tr data-idx="' + idx + '">' +
                    '<td class="cell-strong">' + EOCE.util.escapeHtml(o.RoleDefinitionName) + '</td>' +
                    '<td class="muted nowrap">' + EOCE.util.escapeHtml(EOCE.RBAC_SYSTEMS[self.sysFor(o.RbacSystem)].short) + '</td>' +
                    '<td class="muted cell-words">' + EOCE.util.escapeHtml(o.Service || '—') + '</td>' +
                    '<td>' + EOCE.util.tierBadge(o.EAMTierLevelName) + '</td>' +
                    '<td class="muted">' + EOCE.util.escapeHtml(o.Justification || '') + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';

            html += '<div class="callout" style="margin-top:18px;"><div class="callout-title">Why overwrites exist</div>' +
                'Classification normally derives a role\'s plane from the union of its role actions. Overwrites handle the cases where the role\'s real power is implicit or granted out-of-band &mdash; ensuring these high-impact roles are never under-classified.</div>';

            html += '</div>';
            el.innerHTML = html;

            el.querySelectorAll('#ovrTable tbody tr[data-idx]').forEach(function (tr) {
                tr.addEventListener('click', function () { self.open(overwrites[parseInt(tr.getAttribute('data-idx'), 10)]); });
            });
        });
    },

    open: function (o) {
        var self = this;
        var sysKey = this.sysFor(o.RbacSystem);
        var sys = EOCE.RBAC_SYSTEMS[sysKey];
        var t = EOCE.tier(o.EAMTierLevelName);
        var role = this.roleById[o.RoleDefinitionId];
        var svc = o.Service ? this.serviceActions[o.Service] : null;

        var body = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">' +
            EOCE.util.tierBadge(o.EAMTierLevelName) + '<span class="chip brand">' + EOCE.util.escapeHtml(sys.short) + '</span>' +
            (o.Service ? '<span class="chip">' + EOCE.util.escapeHtml(o.Service) + '</span>' : '') + '</div>';

        body += '<div class="callout control"><div class="callout-title">Justification</div>' + EOCE.util.escapeHtml(o.Justification || '') + '</div>';

        if (role) {
            var info = EOCE.roleOverwriteInfo(o, EOCE.rolePerms(role), role.Classification && role.Classification.EAMTierLevelName);
            body += '<div class="callout implicit"><div class="callout-title">Effect of the overwrite &middot; implicit permissions</div>' +
                (info.actionCount
                    ? 'Classification from this role\'s ' + info.actionCount + ' listed role action' + (info.actionCount === 1 ? '' : 's') + ' would be ' + EOCE.util.tierBadge(info.actionTier, { short: true }) + '. '
                    : 'This role has no listed role actions. ') +
                'The overwrite pins it to ' + EOCE.util.tierBadge(o.EAMTierLevelName, { short: true }) +
                ' to reflect permissions that are not visible in its role actions.' +
                (info.exportedMismatch
                    ? '<div class="muted" style="margin-top:8px;font-size:12px;">Note: the exported classification data reports ' + EOCE.util.tierBadge(info.exportedTier, { short: true }) + ' for this role.</div>'
                    : '') +
                '</div>';
        }

        body += '<dl class="kv"><dt>Role</dt><dd>' + EOCE.util.escapeHtml(o.RoleDefinitionName) + '</dd>' +
            '<dt>Role ID</dt><dd class="cell-mono">' + EOCE.util.escapeHtml(o.RoleDefinitionId) + '</dd>' +
            '<dt>System</dt><dd>' + EOCE.util.escapeHtml(sys.name) + '</dd>' +
            (o.Service ? '<dt>Service</dt><dd>' + EOCE.util.escapeHtml(o.Service) + '</dd>' : '') +
            '<dt>Overwritten to</dt><dd>' + EOCE.util.escapeHtml(t.label) + ' (Tier ' + t.tag + ')</dd></dl>';

        if (svc && svc.actions.length) {
            body += '<div class="section-title">Applicable role actions for "' + EOCE.util.escapeHtml(o.Service) + '"</div>';
            body += '<p class="muted" style="font-size:12.5px;margin:-2px 0 10px;">Role actions that define this service tier in the EntraOps classification.</p>';
            svc.actions.slice(0, 200).forEach(function (a) {
                body += '<div class="action-row" style="border-left:3px solid ' + t.color + ';"><div class="a-name">' + EOCE.util.escapeHtml(a) + '</div>' + EOCE.util.tierBadge(o.EAMTierLevelName, { short: true }) + '</div>';
            });
        }

        if (role) {
            body += '<div style="margin-top:16px;"><a href="#" id="ovrToRole" class="inline-link">Open this role in the Roles explorer &#8594;</a></div>';
        }

        EOCE.app.openDrawer(EOCE.util.escapeHtml(sys.short) + ' overwrite', EOCE.util.escapeHtml(o.RoleDefinitionName), body);

        var link = document.getElementById('ovrToRole');
        if (link) link.addEventListener('click', function (ev) { ev.preventDefault(); EOCE.app.go('roles/' + sysKey + '/' + o.RoleDefinitionId); });
    }
};
