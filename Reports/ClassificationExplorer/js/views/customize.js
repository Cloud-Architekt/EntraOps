/*
 * Customize Overwrites - load, modify or create classification overwrite files
 * (Classification_RoleDefinitionOverwrites.json / Classification_RoleActionOverwrites.json /
 * Classification_ApiPermissionOverwrites.json).
 *
 * Built-in templates live under Classification/Templates, tenant-specific
 * customizations under Classification/<TenantName>. Every overwrite type can be split
 * into tagged files (<BaseName>_<Tag>.json, e.g. Classification_RoleDefinitionOverwrites_PAW.json).
 * Each draft entry stores the file it belongs to in entry._src.file; Export/Save writes
 * every entry back to that file. The editor keeps a draft in localStorage;
 * Import/Export/Save handle the JSON file content. Entries can be
 * added from the shared Review list (roles and role actions, including "add all
 * role actions of a role") or picked from the current primary classification
 * source (tenant-specific template when one exists, built-in template otherwise).
 */
window.EOCE = window.EOCE || {};
EOCE.views = EOCE.views || {};

EOCE.views.customize = (function () {
    'use strict';

    // ---- Static metadata ---------------------------------------------------
    var TYPES = {
        roledef: {
            key: 'roledef',
            label: 'Role Definitions',
            title: 'Role Definition Overwrites',
            fileName: 'Classification_RoleDefinitionOverwrites.json',
            template: EOCE.templateFile('Classification_RoleDefinitionOverwrites.json'),
            // Systems whose EAM cmdlets consume Classification_RoleDefinitionOverwrites.json at runtime.
            systems: ['EntraID', 'IdentityGovernance', 'DeviceManagement', 'Defender'],
            hint: 'Down- or upgrade the tier of an entire role definition, identified by RoleDefinitionId and/or RoleDefinitionName. ' +
                'EntraOps prefers a tenant-specific file (Classification/&lt;TenantName&gt;/) and falls back to the built-in template. Applied at runtime by the Get-EntraOpsPrivilegedEAM* cmdlets (TaggedBy: RoleDefinitionOverwrites).'
        },
        roleaction: {
            key: 'roleaction',
            label: 'Role Actions',
            title: 'Role Action Overwrites',
            fileName: 'Classification_RoleActionOverwrites.json',
            template: EOCE.templateFile('Classification_RoleActionOverwrites.json'),
            // ClassificationParameterScope of Update-EntraOpsClassificationControlPlaneScope.
            systems: ['EntraID', 'IdentityGovernance', 'DeviceManagement', 'Defender'],
            hint: 'Down- or upgrade the tier of individual role definition actions on a scope. ' +
                'EntraOps reads this file <strong>only</strong> from the tenant-specific folder (Classification/&lt;TenantName&gt;/) &mdash; a Templates file serves as a starting point here but is ignored at runtime. ' +
                'Applied at classification file generation time by Update-EntraOpsClassificationControlPlaneScope and baked into the tenant-specific Classification_*.json files. ' +
                'For <strong>Resource Apps (API permissions)</strong>, use the separate "API Permissions" tab instead &mdash; it has its own schema aligned with Classification_ApiPermissions.json.'
        },
        apipermission: {
            key: 'apipermission',
            label: 'API Permissions',
            title: 'API Permission Overwrites',
            fileName: 'Classification_ApiPermissionOverwrites.json',
            template: EOCE.templateFile('Classification_ApiPermissionOverwrites.json'),
            // Only ResourceApps consumes Classification_ApiPermissionOverwrites.json (baked into the
            // tenant-specific Classification_ApiPermissions.json by Update-EntraOpsClassificationControlPlaneScope).
            systems: ['ResourceApps'],
            hint: 'Down- or upgrade the tier of an individual API permission (application or delegated permission on Microsoft Graph or another resource app), identified by PermissionValue. ' +
                'Schema is aligned with an entry of Classification_ApiPermissions.json (PermissionValue/PermissionType/TargetAppId/Category) instead of the role-action/scope-pattern shape used by Classification_RoleActionOverwrites.json. ' +
                'EntraOps reads this file <strong>only</strong> from the tenant-specific folder (Classification/&lt;TenantName&gt;/) &mdash; a Templates file serves as a starting point here but is ignored at runtime. ' +
                'Optionally set Target App ID and/or Permission type (Application/Delegated/All) to pin the overwrite to a specific resource application or permission type &mdash; required to classify a permission that is not yet covered by any entry in Classification_ApiPermissions.json.'
        }
    };

    // Classification-logic definition files used as "primary source" pickers
    // (role actions with their current tier / service). ResourceApps (API permissions) is
    // intentionally excluded here - its picker (below) searches the flat permission catalog instead.
    var DEFINITION_FILES = {
        EntraID: EOCE.templateFile('Classification_AadResources.json'),
        IdentityGovernance: EOCE.templateFile('Classification_IdentityGovernance.json'),
        DeviceManagement: EOCE.templateFile('Classification_DeviceManagement.json'),
        Defender: EOCE.templateFile('Classification_Defender.json')
    };

    // Flat permission catalog used as the picker source for the API Permissions tab
    // (same source Reports/ClassificationExplorer's Permissions view browses).
    var PERMISSION_CATALOG_FILE = EOCE.PERMISSION_SETS.ApiPermissions.file;

    var TIER_CHOICES = ['ControlPlane', 'ManagementPlane', 'UserAccess'];
    var LS_KEY = 'eoce.customize.v1';

    function esc(v) { return EOCE.util.escapeHtml(v); }

    function sysShort(key) {
        if (EOCE.RBAC_SYSTEMS[key]) return EOCE.RBAC_SYSTEMS[key].short;
        return key === 'ResourceApps' ? 'Resource Apps' : key;
    }

    // Reverse map: review items store the RBAC system's short label.
    function sysKeyFromShort(shortLabel) {
        var keys = Object.keys(EOCE.RBAC_SYSTEMS);
        for (var i = 0; i < keys.length; i++) {
            if (EOCE.RBAC_SYSTEMS[keys[i]].short === shortLabel) return keys[i];
        }
        return null;
    }

    // ---- Draft persistence ---------------------------------------------------
    function emptyDraft() { return { entries: [], files: [], source: 'New file (unsaved)', dirty: false }; }

    function loadDrafts() {
        try {
            var raw = window.localStorage.getItem(LS_KEY);
            var d = raw ? JSON.parse(raw) : null;
            if (d && d.roledef && d.roleaction && d.apipermission) {
                // Drafts saved before tagged files were supported: their entries belong to the base file.
                Object.keys(TYPES).forEach(function (type) {
                    var draft = d[type];
                    if (!Array.isArray(draft.entries)) draft.entries = [];
                    draft.entries.forEach(function (e) {
                        if (!e._src) e._src = sourceFor(type, TYPES[type].fileName, false);
                    });
                    if (!Array.isArray(draft.files)) draft.files = draftFiles(type, draft);
                    normalizeDraftFileCase(type, draft);
                });
                return d;
            }
        } catch (e) { /* private mode / corrupt draft */ }
        return { roledef: emptyDraft(), roleaction: emptyDraft(), apipermission: emptyDraft() };
    }

    function persistDrafts(drafts) {
        try { window.localStorage.setItem(LS_KEY, JSON.stringify(drafts)); } catch (e) { /* ignore */ }
    }

    // ---- Overwrite files and entry origin ------------------------------------
    function fileStem(fileName) { return String(fileName).replace(/\.json$/i, ''); }
    function baseName(path) { return String(path).split(/[\\\/]/).pop(); }

    // Returns { type, file, tag, suffix } for <BaseName>.json (tag null) or <BaseName>_<Suffix>.json.
    // The tag is the text after the last "_" (same rule as Get-EntraOpsClassificationOverwriteFile).
    function parseOverwriteFileName(fileName) {
        var name = baseName(fileName);
        var keys = Object.keys(TYPES);
        for (var i = 0; i < keys.length; i++) {
            var base = TYPES[keys[i]].fileName;
            if (name.toLowerCase() === base.toLowerCase()) return { type: keys[i], file: base, tag: null, suffix: null };
            var prefix = fileStem(base).toLowerCase() + '_';
            if (name.toLowerCase().indexOf(prefix) === 0 && /\.json$/i.test(name)) {
                var suffix = fileStem(name).slice(prefix.length);
                var tag = suffix.split('_').pop();
                if (tag) return { type: keys[i], file: fileStem(base) + '_' + suffix + '.json', tag: tag, suffix: suffix };
            }
        }
        return null;
    }

    // EntraOps only loads <BaseName>.json and <BaseName>_<Tag>.json: a file with another name is
    // mapped to one of these names (its own name would never be loaded).
    function canonicalFileName(type, tag) {
        return tag ? fileStem(TYPES[type].fileName) + '_' + tag + '.json' : TYPES[type].fileName;
    }

    function sourceFor(type, fileName, custom) {
        var parsed = parseOverwriteFileName(fileName);
        var file = parsed && parsed.type === type ? parsed.file : canonicalFileName(type, null);
        return { file: file, tag: parsed && parsed.type === type ? parsed.tag : null, custom: !!custom, removed: false };
    }

    // "Base" or the tag of a file; the full suffix when two files of the draft share the tag.
    function fileLabel(type, draft, file) {
        var parsed = parseOverwriteFileName(file);
        if (!parsed || !parsed.tag) return 'Base';
        var shared = draftFiles(type, draft).some(function (f) {
            var other = parseOverwriteFileName(f);
            return f !== file && other && other.tag && other.tag.toLowerCase() === parsed.tag.toLowerCase();
        });
        return shared ? parsed.suffix : parsed.tag;
    }

    function originLabel(type, draft, e) {
        var label = fileLabel(type, draft, targetFile(type, e));
        return e._src && e._src.custom ? 'Custom - ' + label : label;
    }

    function matchesOrigin(type, e, filter) {
        if (!filter) return true;
        if (filter === 'custom') return !!(e._src && e._src.custom);
        return 'file:' + targetFile(type, e) === filter;
    }

    // Entries of different files for the same item (Import-EntraOpsClassificationOverwrites lists them too).
    function overlapKeys(type, e) {
        if (type === 'roledef') {
            var svc = !e.Service || e.Service === '*' ? '*' : e.Service.toLowerCase();
            return [e.RoleDefinitionId, e.RoleDefinitionName].filter(Boolean).map(function (id) { return e.RbacSystem + '|' + id.toLowerCase() + '|' + svc; });
        }
        if (type === 'apipermission') {
            return [(e.PermissionValue + '|' + (e.PermissionType || 'All') + '|' + e.TargetAppId).toLowerCase()];
        }
        var keys = [];
        (e.RoleDefinitionActions || []).forEach(function (a) {
            (e.RoleAssignmentScopeName || []).forEach(function (sc) { keys.push((e.RbacSystem + '|' + a + '|' + sc).toLowerCase()); });
        });
        return keys;
    }

    function findOverlaps(type, entries) {
        var byKey = {};
        entries.forEach(function (e) {
            if (e._src && e._src.removed) return;
            overlapKeys(type, e).forEach(function (k) {
                var item = byKey[k] || (byKey[k] = { entry: e, files: [] });
                var f = targetFile(type, e);
                if (item.files.indexOf(f) === -1) item.files.push(f);
            });
        });
        var seen = {};
        return Object.keys(byKey).map(function (k) { return byKey[k]; }).filter(function (item) {
            if (item.files.length < 2) return false;
            var id = item.files.join('|') + '|' + entryTitle(type, item.entry);
            if (seen[id]) return false;
            seen[id] = true;
            return true;
        });
    }

    function entryTitle(type, e) {
        if (type === 'roledef') return (e.RoleDefinitionName || e.RoleDefinitionId) + (e.Service && e.Service !== '*' ? ' (' + e.Service + ')' : ' (whole role)');
        if (type === 'apipermission') return e.PermissionValue;
        return (e.RoleDefinitionActions || []).join(', ');
    }

    var PRECEDENCE = {
        roledef: 'An entry matching the role by RoleDefinitionId takes precedence over one matching only by name, and a whole-role entry (empty or "*" Service) is applied after service-specific entries and replaces them; otherwise the entry of the later file takes precedence.',
        roleaction: 'The entry of the later file is applied last and takes precedence.',
        apipermission: 'The entry of the later file is applied last and takes precedence.'
    };

    function targetFile(type, e) {
        return (e._src && e._src.file) || TYPES[type].fileName;
    }

    // macOS and Windows file systems ignore case: a file name that differs only by case from a file the
    // draft already writes resolves to that file's spelling, so Save never writes the same file twice.
    function resolveFileName(files, file) {
        var lower = String(file).toLowerCase();
        for (var i = 0; i < files.length; i++) {
            if (String(files[i]).toLowerCase() === lower) return files[i];
        }
        return file;
    }

    function normalizeDraftFileCase(type, draft) {
        var known = [];
        function resolve(f) {
            var r = resolveFileName(known, f);
            if (r === f && known.indexOf(f) === -1) known.push(f);
            return r;
        }
        draft.files = (draft.files || []).map(resolve).filter(function (f, i, arr) { return arr.indexOf(f) === i; });
        draft.entries.forEach(function (e) { if (e._src && e._src.file) e._src.file = resolve(e._src.file); });
    }

    // Files the draft writes on export: every loaded or imported file (also when all of its entries were
    // removed, so the emptied file replaces the old one) and every file an entry belongs to.
    function draftFiles(type, draft) {
        var files = [];
        function add(f) { if (f && files.indexOf(f) === -1) files.push(f); }
        (draft.files || []).forEach(add);
        draft.entries.forEach(function (e) { add(targetFile(type, e)); });
        if (!files.length) add(TYPES[type].fileName);
        // Base file first, then the tagged files by name (the order EntraOps applies them in).
        return files.sort(function (a, b) {
            if (a === TYPES[type].fileName) return -1;
            if (b === TYPES[type].fileName) return 1;
            return a.toLowerCase() < b.toLowerCase() ? -1 : (a.toLowerCase() > b.toLowerCase() ? 1 : 0);
        });
    }

    // ---- Entry model ---------------------------------------------------------
    function toArray(v) {
        if (v === undefined || v === null || v === '') return [];
        return (Array.isArray(v) ? v : [v]).map(function (x) { return String(x); }).filter(Boolean);
    }

    function normalizeEntry(type, raw) {
        var e = raw || {};
        var base = {
            RbacSystem: e.RbacSystem && TYPES[type].systems.indexOf(String(e.RbacSystem)) !== -1 ? String(e.RbacSystem) : (e.RbacSystem ? String(e.RbacSystem) : TYPES[type].systems[0]),
            EAMTierLevelName: TIER_CHOICES.indexOf(String(e.EAMTierLevelName)) !== -1 ? String(e.EAMTierLevelName) : (e.EAMTierLevelName ? String(e.EAMTierLevelName) : ''),
            Service: e.Service ? String(e.Service) : '',
            Justification: e.Justification ? String(e.Justification) : ''
        };
        if (type === 'roledef') {
            base.RoleDefinitionId = e.RoleDefinitionId ? String(e.RoleDefinitionId) : '';
            base.RoleDefinitionName = e.RoleDefinitionName ? String(e.RoleDefinitionName) : '';
        } else if (type === 'apipermission') {
            // Category is the API permission catalog's equivalent of Service - stored in the same
            // internal `Service` field so the generic Service input/label can be reused, but
            // serialized back out as `Category` (see serializeEntries).
            base.PermissionValue = e.PermissionValue ? String(e.PermissionValue) : '';
            base.PermissionType = ['Application', 'Delegated', 'All'].indexOf(String(e.PermissionType)) !== -1 ? String(e.PermissionType) : '';
            base.TargetAppId = e.TargetAppId ? String(e.TargetAppId) : '';
        } else {
            base.RoleDefinitionActions = toArray(e.RoleDefinitionActions);
            base.RoleAssignmentScopeName = toArray(e.RoleAssignmentScopeName);
            if (!base.RoleAssignmentScopeName.length) base.RoleAssignmentScopeName = ['/*'];
        }
        return base;
    }

    function serializeEntries(type, entries) {
        return entries.map(function (e) {
            var tier = EOCE.TIERS[e.EAMTierLevelName];
            var out = { RbacSystem: e.RbacSystem };
            if (type === 'roledef') {
                if (e.RoleDefinitionId) out.RoleDefinitionId = e.RoleDefinitionId;
                if (e.RoleDefinitionName) out.RoleDefinitionName = e.RoleDefinitionName;
            } else if (type === 'apipermission') {
                out.PermissionValue = e.PermissionValue;
                if (e.PermissionType) out.PermissionType = e.PermissionType;
                if (e.TargetAppId) out.TargetAppId = e.TargetAppId;
            } else {
                out.RoleDefinitionActions = e.RoleDefinitionActions.slice();
                out.RoleAssignmentScopeName = e.RoleAssignmentScopeName.length ? e.RoleAssignmentScopeName.slice() : ['/*'];
            }
            out.EAMTierLevelName = e.EAMTierLevelName;
            out.EAMTierLevelTagValue = tier ? tier.tag : '';
            if (e.Service) { out[type === 'apipermission' ? 'Category' : 'Service'] = e.Service; }
            out.Justification = e.Justification || '';
            return out;
        });
    }

    // Issues that would make Import-EntraOpsClassificationOverwrites skip the entry.
    function validateEntries(type, entries) {
        var issues = [];
        entries.forEach(function (e, i) {
            if (e._src && e._src.removed) return;
            var label = 'Entry ' + (i + 1);
            if (type === 'roledef' && !e.RoleDefinitionId && !e.RoleDefinitionName) {
                issues.push({ idx: i, msg: label + ': RoleDefinitionId or RoleDefinitionName is required.' });
            }
            if (type === 'roleaction' && (!e.RoleDefinitionActions || !e.RoleDefinitionActions.length)) {
                issues.push({ idx: i, msg: label + ': at least one role definition action is required.' });
            }
            if (type === 'apipermission' && !e.PermissionValue) {
                issues.push({ idx: i, msg: label + ': PermissionValue is required.' });
            }
            if (TIER_CHOICES.indexOf(e.EAMTierLevelName) === -1) {
                issues.push({ idx: i, msg: label + ': EAMTierLevelName must be one of ' + TIER_CHOICES.join(', ') + '.' });
            }
            if (!e.Justification) {
                issues.push({ idx: i, msg: label + ': a Justification is mandatory to document the classification change.' });
            }
        });
        return issues;
    }

    // ---- Source resolution ---------------------------------------------------
    function sourceOptions(type) {
        var t = TYPES[type];
        var opts = [{ key: 'template', label: 'Built-in template (' + EOCE.TEMPLATE_BASE + ')', paths: [t.template] }];
        EOCE.TENANTS.forEach(function (tn) {
            if (!tn || !tn.name) return;
            var prefix = 'Classification/' + tn.name + '/';
            var paths = (tn.files || []).filter(function (p) {
                if (p.indexOf(prefix) !== 0) return false;
                var parsed = parseOverwriteFileName(p);
                return parsed && parsed.type === type;
            });
            if (paths.length) {
                var tags = paths.map(function (p) { return parseOverwriteFileName(p).tag; }).filter(Boolean);
                // Role definitions: without a tenant base file EntraOps uses the template base file.
                // Load it as the base, so saving a tenant base file keeps its entries.
                var templateBase = type === 'roledef' && !paths.some(function (p) { return !parseOverwriteFileName(p).tag; });
                if (templateBase) paths.unshift(t.template);
                opts.push({
                    key: 'tenant:' + tn.name, paths: paths,
                    label: tn.name + ' (tenant-specific' + (tags.length ? ', tags: ' + tags.join(', ') : '') + (templateBase ? ', base from template' : '') + ')'
                });
            }
        });
        return opts;
    }

    // Primary classification source: tenant-specific copy when one exists
    // (selected variant first, otherwise the single discovered tenant), else template.
    function primaryPath(templatePath) {
        var variant = EOCE.getVariant();
        var p = null;
        if (variant !== EOCE.VARIANT_TEMPLATE) p = EOCE.tenantFileFor(variant, templatePath);
        if (!p && EOCE.TENANTS.length === 1) p = EOCE.tenantFileFor(EOCE.TENANTS[0].name, templatePath);
        return p || templatePath;
    }

    function sourceLabelForPath(path) {
        if (path.indexOf(EOCE.TEMPLATE_BASE + '/') === 0) return 'built-in template';
        var m = /^Classification\/([^\/]+)\//.exec(path);
        return m ? 'tenant-specific (' + m[1] + ')' : path;
    }

    // Flatten a tier-definition file into [{ action, service, tier }] (first occurrence wins).
    function flattenDefinition(defArray) {
        var seen = {}, out = [];
        (defArray || []).forEach(function (tierObj) {
            var tier = tierObj && tierObj.EAMTierLevelName;
            ((tierObj && tierObj.TierLevelDefinition) || []).forEach(function (def) {
                ((def && def.RoleDefinitionActions) || []).forEach(function (a) {
                    var k = String(a).toLowerCase();
                    if (seen[k]) return;
                    seen[k] = true;
                    out.push({
                        action: String(a), service: (def && def.Service) || '', tier: tier || 'Unclassified',
                        resourceAppId: (def && def.ResourceAppId) || '', resourceScope: (def && def.ResourceScope) || ''
                    });
                });
            });
        });
        return out;
    }

    // ---- Roles index (for the role picker and review-list expansion) ----------
    var rolesIndexPromise = null;
    function loadRolesIndex() {
        if (rolesIndexPromise) return rolesIndexPromise;
        // Azure RBAC is excluded: the overwrite files are not consumed by the Azure EAM pipeline.
        var keys = EOCE.rolesSystemKeys().filter(function (k) { return k !== 'Azure'; });
        rolesIndexPromise = Promise.all(keys.map(function (k) {
            return EOCE.data.load(EOCE.RBAC_SYSTEMS[k].file).catch(function () { return []; });
        })).then(function (sets) {
            var list = [], byId = {};
            keys.forEach(function (k, i) {
                (sets[i] || []).forEach(function (r) {
                    var actions = EOCE.rolePerms(r).map(function (p) { return p.AuthorizedResourceAction; }).filter(Boolean);
                    var item = {
                        sysKey: k,
                        id: r.RoleId || '',
                        name: r.RoleName || '',
                        tier: (r.Classification && r.Classification.EAMTierLevelName) || 'Unclassified',
                        actions: actions
                    };
                    list.push(item);
                    byId[k + '|' + item.id] = item;
                });
            });
            return { list: list, byId: byId };
        });
        return rolesIndexPromise;
    }

    // ---- Review list helpers ---------------------------------------------------
    function reviewItems() {
        return window.EOReview ? EOReview.all() : [];
    }

    // Resolve a review item into { kind, sysKey, roleId?, action?, name }.
    function resolveReviewItem(item) {
        var m;
        if (item.kind === 'Role') {
            m = /#roles\/([^\/]+)\/(.+)$/.exec(item.hash || '');
            return { kind: 'role', sysKey: m ? decodeURIComponent(m[1]) : sysKeyFromShort(item.system), roleId: m ? decodeURIComponent(m[2]) : null, name: item.name };
        }
        if (item.kind === 'Role action') {
            m = /#actions\/([^\/]+)\/(.+)$/.exec(item.hash || '');
            return { kind: 'action', sysKey: m ? decodeURIComponent(m[1]) : sysKeyFromShort(item.system), action: m ? decodeURIComponent(m[2]) : item.name, name: item.name };
        }
        return null;
    }

    // ---- File import ------------------------------------------------------------
    function readJsonFile(file) {
        return new Promise(function (resolve, reject) {
            var reader = new FileReader();
            reader.onload = function () {
                try {
                    var arr = JSON.parse(String(reader.result));
                    if (!Array.isArray(arr)) throw new Error('Expected a JSON array of overwrite entries.');
                    resolve({ name: file.name, arr: arr });
                } catch (err) {
                    reject(new Error('"' + file.name + '": ' + (err && err.message ? err.message : err)));
                }
            };
            reader.onerror = function () { reject(new Error('"' + file.name + '": the file could not be read.')); };
            reader.readAsText(file);
        });
    }

    function originFilterOptions(type, draft) {
        var opts = [{ value: '', label: 'All origins' }];
        draftFiles(type, draft).forEach(function (f) {
            opts.push({ value: 'file:' + f, label: fileLabel(type, draft, f) + ' (' + f + ')' });
        });
        if (draft.entries.some(function (e) { return e._src && e._src.custom; })) opts.push({ value: 'custom', label: 'Custom (changed in the editor)' });
        return opts;
    }

    // ---- File download / save ---------------------------------------------------
    function downloadJson(fileName, jsonText) {
        var blob = new Blob([jsonText], { type: 'application/json;charset=utf-8;' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Both savers reject with err.picked (the user chose a target), err.written (file names written so
    // far) and err.failed (the file being written).
    function saveWithPicker(fileName, jsonText) {
        if (!window.showSaveFilePicker) return Promise.reject(new Error('unsupported'));
        var picked = false;
        return window.showSaveFilePicker({
            suggestedName: fileName,
            types: [{ description: 'JSON', accept: { 'application/json': ['.json'] } }]
        }).then(function (handle) {
            picked = true;
            return handle.createWritable().then(function (writable) {
                return writable.write(jsonText).then(function () { return writable.close(); });
            });
        }).catch(function (err) {
            err = err || new Error('unknown error');
            err.picked = picked;
            err.written = [];
            err.failed = fileName;
            throw err;
        });
    }

    function saveAllToDirectory(outputs) {
        var picked = false, written = [], current = null;
        return window.showDirectoryPicker({ mode: 'readwrite' }).then(function (dir) {
            picked = true;
            return outputs.reduce(function (chain, o) {
                return chain.then(function () {
                    current = o.fileName;
                    return dir.getFileHandle(o.fileName, { create: true }).then(function (handle) {
                        return handle.createWritable().then(function (writable) {
                            return writable.write(o.jsonText).then(function () { return writable.close(); });
                        });
                    }).then(function () { written.push(o.fileName); });
                });
            }, Promise.resolve());
        }).catch(function (err) {
            err = err || new Error('unknown error');
            err.picked = picked;
            err.written = written;
            err.failed = current;
            throw err;
        });
    }

    // ---- Inline error banner ---------------------------------------------------
    // Host element: #custError in the main view, #cfError inside the add/edit blade.
    function showError(hostId, message) {
        var host = document.getElementById(hostId);
        if (!host) return;
        host.innerHTML = '<div class="callout attack" role="alert" style="margin-bottom:14px;">' +
            '<button type="button" class="btn small" style="float:right;" data-dismiss title="Dismiss" aria-label="Dismiss error">&#10005;</button>' +
            '<div class="callout-title">&#9888; Error</div>' +
            '<div style="white-space:pre-line;">' + esc(message) + '</div></div>';
        host.querySelector('[data-dismiss]').addEventListener('click', function () { host.innerHTML = ''; });
        if (host.firstChild && host.firstChild.scrollIntoView) host.firstChild.scrollIntoView({ block: 'nearest' });
    }

    function clearError(hostId) {
        var host = document.getElementById(hostId);
        if (host) host.innerHTML = '';
    }

    // ==========================================================================
    var view = {
        state: { type: 'roledef', origin: '' },
        drafts: null,
        form: null,

        draft: function () { return this.drafts[this.state.type]; },

        markDirty: function () {
            this.draft().dirty = true;
            persistDrafts(this.drafts);
        },

        // ---- Main view ------------------------------------------------------
        render: function (el, params) {
            var self = this;
            this.el = el;
            if (!this.drafts) this.drafts = loadDrafts();
            if (params && params[0] && TYPES[params[0]]) this.state.type = params[0];

            el.innerHTML =
                '<div class="view">' +
                '<div class="page-head"><h1>Customize Overwrites</h1>' +
                '<p>Create or modify EntraOps classification overwrite files: pin an entire <strong>role definition</strong> to a tier, down-/upgrade individual <strong>role actions</strong> on a scope, or down-/upgrade an individual <strong>API permission</strong>. ' +
                'Load the built-in template or a tenant-specific file set, or import one or more files (base and tagged <code>_&lt;Tag&gt;.json</code> files), edit the entries, then export or save the JSON files. Store your customization as <code>Classification/&lt;TenantName&gt;/&lt;file&gt;</code> in your EntraOps repository.</p></div>' +
                '<div id="custToolbar"></div>' +
                '<div id="custError"></div>' +
                '<div id="custIssues"></div>' +
                '<div class="table-wrap"><table class="grid-table" id="custTable"></table></div>' +
                '<div class="cust-footer" id="custFooter"></div>' +
                '<div class="callout" style="margin-top:18px;" id="custHint"></div>' +
                '</div>';

            this.renderToolbar();
            this.renderTable();
            this.renderFooter();
            this.renderHint();
            return Promise.resolve();
        },

        renderToolbar: function () {
            var self = this;
            var type = this.state.type;
            var d = this.draft();
            var opts = sourceOptions(type);

            var html = '<div class="toolbar">';
            html += '<div class="seg-group" id="custTypeSeg">';
            Object.keys(TYPES).forEach(function (k) {
                html += '<button class="seg' + (type === k ? ' active' : '') + '" data-type="' + k + '">' + esc(TYPES[k].label) + '</button>';
            });
            html += '</div>';

            html += '<select class="filter" id="custSource" title="Overwrite file to load">';
            opts.forEach(function (o) {
                html += '<option value="' + esc(o.key) + '">' + esc(o.label) + '</option>';
            });
            html += '</select>';
            html += '<button class="btn" id="custLoad" title="Load the selected overwrite file into the editor (replaces the current draft)">Load</button>';
            html += '<button class="btn" id="custNew" title="Start a new, empty overwrite file">New</button>';
            html += '<button class="btn" id="custImport" title="Import one or more overwrite JSON files from disk (base file and tagged files, e.g. ' + esc(fileStem(TYPES[type].fileName)) + '_PAW.json)">Import&hellip;</button>';
            html += '<input type="file" id="custImportFile" accept=".json,application/json" multiple hidden>';
            html += '<select class="filter" id="custOriginFilter" title="Show the entries of one origin">';
            originFilterOptions(type, d).forEach(function (o) {
                html += '<option value="' + esc(o.value) + '"' + (self.state.origin === o.value ? ' selected' : '') + '>' + esc(o.label) + '</option>';
            });
            html += '</select>';

            html += '<span class="toolbar-meta" id="custMeta"></span>';
            html += '</div>';
            html += '<div class="cust-status" id="custStatus"></div>';

            document.getElementById('custToolbar').innerHTML = html;
            this.updateStatus();

            document.getElementById('custTypeSeg').addEventListener('click', function (e) {
                var b = e.target.closest('[data-type]'); if (!b) return;
                self.state.type = b.getAttribute('data-type');
                self.state.origin = '';
                clearError('custError');
                self.renderToolbar(); self.renderTable(); self.renderFooter(); self.renderHint();
            });
            document.getElementById('custLoad').addEventListener('click', function () {
                var sel = document.getElementById('custSource');
                var opt = opts.filter(function (o) { return o.key === sel.value; })[0];
                if (!opt) return;
                if (self.draft().dirty && !window.confirm('Replace the current draft (' + self.draft().entries.length + ' entries) with "' + opt.label + '"?')) return;
                var loadType = self.state.type;
                Promise.all(opt.paths.map(function (path) {
                    return EOCE.data.loadRaw(path).then(function (arr) { return { path: path, arr: arr }; }, function (err) {
                        throw new Error('"' + path + '": ' + (err && err.message ? err.message : err));
                    });
                })).then(function (loaded) {
                    var draft = { entries: [], files: [], source: opt.label, dirty: false };
                    loaded.forEach(function (f) {
                        var src = sourceFor(loadType, f.path, false);
                        draft.files.push(src.file);
                        (Array.isArray(f.arr) ? f.arr : []).forEach(function (raw) {
                            var e = normalizeEntry(loadType, raw);
                            e._src = JSON.parse(JSON.stringify(src));
                            draft.entries.push(e);
                        });
                    });
                    self.drafts[loadType] = draft;
                    self.state.origin = '';
                    persistDrafts(self.drafts);
                    clearError('custError');
                    self.renderToolbar(); self.renderTable(); self.renderFooter();
                }).catch(function (err) {
                    showError('custError', 'Could not load ' + (err && err.message ? err.message : err) +
                        '\n\nThe file may not exist (yet) or the app is running without an embedded data bundle.');
                });
            });
            document.getElementById('custNew').addEventListener('click', function () {
                if (self.draft().dirty && !window.confirm('Discard the current draft (' + self.draft().entries.length + ' entries) and start empty?')) return;
                self.drafts[self.state.type] = emptyDraft();
                self.state.origin = '';
                persistDrafts(self.drafts);
                self.renderToolbar(); self.renderTable(); self.renderFooter();
            });
            document.getElementById('custOriginFilter').addEventListener('change', function (e) {
                self.state.origin = e.target.value;
                self.renderTable();
            });
            document.getElementById('custImport').addEventListener('click', function () {
                document.getElementById('custImportFile').click();
            });
            document.getElementById('custImportFile').addEventListener('change', function (e) {
                var files = Array.prototype.slice.call((e.target.files) || []);
                e.target.value = '';
                if (!files.length) return;
                Promise.all(files.map(readJsonFile)).then(function (results) {
                    self.importFiles(results);
                }).catch(function (err) {
                    showError('custError', 'Import failed: ' + (err && err.message ? err.message : err));
                });
            });
        },

        // Merge imported files into the drafts. A file name of another overwrite type goes to that
        // type's draft; any other name goes to the current type (a "_<Tag>" suffix keeps its tag).
        // Entries of a file that is already in the draft are replaced by the imported ones.
        importFiles: function (results) {
            var self = this;
            var byType = {};
            var renamed = [];
            var knownByType = {};
            results.forEach(function (r) {
                var parsed = parseOverwriteFileName(r.name);
                var type = parsed ? parsed.type : self.state.type;
                var tag = parsed ? parsed.tag : (fileStem(r.name).indexOf('_') !== -1 ? fileStem(r.name).split('_').pop() : null);
                var known = knownByType[type] || (knownByType[type] = draftFiles(type, self.drafts[type]).slice());
                var file = resolveFileName(known, parsed ? parsed.file : canonicalFileName(type, tag));
                if (known.indexOf(file) === -1) known.push(file);
                if (file !== baseName(r.name)) renamed.push(r.name + ' \u2192 ' + file);
                (byType[type] = byType[type] || []).push({ file: file, tag: tag, name: r.name, arr: r.arr });
            });
            // Two imported files that map to the same file name are combined, not replaced
            var combined = [];
            Object.keys(byType).forEach(function (type) {
                var counts = {};
                byType[type].forEach(function (f) { counts[f.file] = (counts[f.file] || 0) + 1; });
                Object.keys(counts).forEach(function (f) { if (counts[f] > 1) combined.push(f); });
            });

            var types = Object.keys(byType);
            var replaced = [];
            types.forEach(function (type) {
                byType[type].forEach(function (f) {
                    if (self.drafts[type].entries.some(function (e) { return targetFile(type, e) === f.file; })) replaced.push(f.file);
                });
            });
            if (replaced.length && !window.confirm('Replace the entries of ' + replaced.join(', ') + ' in the current draft with the imported file(s)?')) return;

            types.forEach(function (type) {
                var draft = self.drafts[type];
                var importedFiles = byType[type].map(function (f) { return f.file; });
                draft.entries = draft.entries.filter(function (e) { return importedFiles.indexOf(targetFile(type, e)) === -1; });
                byType[type].forEach(function (f) {
                    if (draft.files.indexOf(f.file) === -1) draft.files.push(f.file);
                    f.arr.forEach(function (raw) {
                        var e = normalizeEntry(type, raw);
                        e._src = { file: f.file, tag: f.tag, custom: false, removed: false };
                        draft.entries.push(e);
                    });
                });
                var names = byType[type].map(function (f) { return f.name; });
                draft.source = 'Imported: ' + names.join(', ');
                draft.dirty = true;
            });
            persistDrafts(this.drafts);
            if (types.indexOf(this.state.type) === -1) this.state.type = types[0];
            this.state.origin = '';
            clearError('custError');
            this.renderToolbar(); this.renderTable(); this.renderFooter(); this.renderHint();
            var notes = [];
            if (renamed.length) notes.push('Imported under the file name EntraOps loads (export writes these names):\n' + renamed.join('\n'));
            if (combined.length) notes.push('Several imported files map to the same file; their entries were combined:\n' + combined.join('\n'));
            if (notes.length) showError('custError', notes.join('\n\n'));
        },

        updateStatus: function () {
            var type = this.state.type;
            var d = this.draft();
            var statusEl = document.getElementById('custStatus');
            var metaEl = document.getElementById('custMeta');
            var active = d.entries.filter(function (e) { return !(e._src && e._src.removed); });
            if (metaEl) metaEl.textContent = active.length + ' entr' + (active.length === 1 ? 'y' : 'ies');
            if (statusEl) {
                var chips = draftFiles(type, d).map(function (f) {
                    var count = active.filter(function (e) { return targetFile(type, e) === f; }).length;
                    return '<span class="chip brand" title="Exported as ' + esc(f) + '">' + esc(f) + ' (' + count + ')</span>';
                }).join(' ');
                var custom = d.entries.filter(function (e) { return e._src && e._src.custom; }).length;
                statusEl.innerHTML = chips + ' ' +
                    '<span class="muted">Source: ' + esc(d.source) + '</span>' +
                    (custom ? ' <span class="chip warn" title="Entries added, edited or removed in the editor">' + custom + ' custom change' + (custom === 1 ? '' : 's') + '</span>' : '') +
                    (d.dirty ? ' <span class="chip warn" title="The draft differs from the loaded source and has not been exported/saved yet">unsaved changes</span>' : '');
            }
        },

        renderTable: function () {
            var self = this;
            var type = this.state.type;
            var d = this.draft();
            var issues = validateEntries(type, d.entries);
            var issueIdx = {};
            issues.forEach(function (i) { issueIdx[i.idx] = true; });

            var overlaps = findOverlaps(type, d.entries);
            var overlapHtml = overlaps.length
                ? '<div class="callout" style="margin-bottom:14px;" id="custOverlaps"><div class="callout-title">' + overlaps.length + ' item' + (overlaps.length === 1 ? ' is' : 's are') + ' overwritten in more than one file</div>' +
                esc(PRECEDENCE[type]) + '<ul style="margin:8px 0 0 18px;padding:0;">' +
                overlaps.slice(0, 10).map(function (o) { return '<li><strong>' + esc(entryTitle(type, o.entry)) + '</strong>: ' + esc(o.files.join(', ')) + '</li>'; }).join('') +
                (overlaps.length > 10 ? '<li>&hellip; and ' + (overlaps.length - 10) + ' more</li>' : '') +
                '</ul></div>'
                : '';
            var issuesEl = document.getElementById('custIssues');
            if (issuesEl) {
                issuesEl.innerHTML = overlapHtml + (issues.length
                    ? '<div class="callout attack" style="margin-bottom:14px;"><div class="callout-title">&#9888; ' + issues.length + ' validation issue' + (issues.length === 1 ? '' : 's') + '</div>' +
                    'EntraOps skips invalid entries with a warning when loading the file.<ul style="margin:8px 0 0 18px;padding:0;">' +
                    issues.slice(0, 10).map(function (i) { return '<li>' + esc(i.msg) + '</li>'; }).join('') +
                    (issues.length > 10 ? '<li>&hellip; and ' + (issues.length - 10) + ' more</li>' : '') +
                    '</ul></div>'
                    : '');
            }

            var html = '<thead><tr>';
            if (type === 'roledef') {
                html += '<th>Role</th><th class="nowrap">System</th><th class="nowrap">Overwrite to</th><th class="nowrap">Service</th><th>Justification</th>';
            } else if (type === 'apipermission') {
                html += '<th>Permission</th><th class="nowrap">Type / App</th><th class="nowrap">System</th><th class="nowrap">Overwrite to</th><th>Justification</th>';
            } else {
                html += '<th>Role actions</th><th class="nowrap">Scope</th><th class="nowrap">System</th><th class="nowrap">Overwrite to</th><th>Justification</th>';
            }
            html += '<th class="nowrap">Origin</th><th class="no-sort"></th>';
            html += '</tr></thead><tbody>';

            var origin = this.state.origin || '';
            var shown = d.entries.filter(function (e) { return matchesOrigin(type, e, origin); });
            if (!d.entries.length) {
                html += '<tr><td colspan="7"><div class="empty"><div class="big">&#9998;</div>No overwrite entries yet.<br>' +
                    'Load a template or tenant file, import one or more JSON files, or add an entry &mdash; also directly from your Review list.</div></td></tr>';
            } else if (!shown.length) {
                html += '<tr><td colspan="7"><div class="empty">No entries with the selected origin.</div></td></tr>';
            } else {
                d.entries.forEach(function (e, idx) {
                    if (!matchesOrigin(type, e, origin)) return;
                    var removed = !!(e._src && e._src.removed);
                    var custom = !!(e._src && e._src.custom);
                    var label = originLabel(type, d, e);
                    var originTitle = removed ? 'Removed in the editor; not written to ' + targetFile(type, e)
                        : (custom ? 'Added or edited in the editor; written to ' : 'From ') + targetFile(type, e);
                    var originChip = '<span class="chip ' + (custom ? 'warn' : (label === 'Base' ? '' : 'brand')) + ' cust-origin" title="' + esc(originTitle) + '">' + esc(label) + '</span>' +
                        (removed ? ' <span class="muted" style="font-size:11px;">removed</span>' : '');
                    var warn = issueIdx[idx] ? ' <span class="chip attack" title="This entry has validation issues">&#9888;</span>' : '';
                    var tierCell = TIER_CHOICES.indexOf(e.EAMTierLevelName) !== -1 ? EOCE.util.tierBadge(e.EAMTierLevelName) : '<span class="chip">' + esc(e.EAMTierLevelName || '—') + '</span>';
                    html += '<tr data-idx="' + idx + '"' + (removed ? ' class="cust-removed"' : '') + '>';
                    if (type === 'roledef') {
                        html += '<td><span class="cell-strong">' + esc(e.RoleDefinitionName || '(by ID only)') + '</span>' + warn +
                            (e.RoleDefinitionId ? '<div class="cell-mono muted" style="font-size:11px;">' + esc(e.RoleDefinitionId) + '</div>' : '') + '</td>' +
                            '<td class="muted nowrap">' + esc(sysShort(e.RbacSystem)) + '</td>' +
                            '<td>' + tierCell + '</td>' +
                            '<td class="muted nowrap">' + esc(e.Service || '—') + '</td>';
                    } else if (type === 'apipermission') {
                        html += '<td><span class="cell-strong cell-mono">' + esc(e.PermissionValue || '(not set)') + '</span>' + warn + '</td>' +
                            '<td class="muted nowrap">' + esc(e.PermissionType || 'All') +
                            (e.TargetAppId ? '<div class="cell-mono muted" style="font-size:11px;">' + esc(e.TargetAppId) + '</div>' : '') + '</td>' +
                            '<td class="muted nowrap">' + esc(sysShort(e.RbacSystem)) + '</td>' +
                            '<td>' + tierCell + '</td>';
                    } else {
                        var acts = e.RoleDefinitionActions || [];
                        var preview = acts.slice(0, 3).map(function (a) { return '<div class="cell-mono" style="font-size:11.5px;">' + esc(a) + '</div>'; }).join('');
                        html += '<td><span class="cell-strong">' + acts.length + ' action' + (acts.length === 1 ? '' : 's') + '</span>' + warn + preview +
                            (acts.length > 3 ? '<div class="muted" style="font-size:11px;">&hellip; ' + (acts.length - 3) + ' more</div>' : '') + '</td>' +
                            '<td class="muted nowrap cell-mono" style="font-size:11.5px;">' + esc((e.RoleAssignmentScopeName || []).join(', ')) + '</td>' +
                            '<td class="muted nowrap">' + esc(sysShort(e.RbacSystem)) + '</td>' +
                            '<td>' + tierCell + '</td>';
                    }
                    html += '<td class="muted">' + esc((e.Justification || '').length > 140 ? e.Justification.slice(0, 140) + '…' : (e.Justification || '')) + '</td>' +
                        '<td class="nowrap">' + originChip + '</td>' +
                        '<td class="nowrap" style="text-align:right;">' +
                        (removed
                            ? '<button class="btn small" data-restore="' + idx + '" title="Keep this entry in ' + esc(targetFile(type, e)) + '">Restore</button>'
                            : '<button class="btn small" data-edit="' + idx + '">Edit</button> ' +
                            '<button class="btn small" data-del="' + idx + '" title="Remove this entry">&#10005;</button>') + '</td>';
                    html += '</tr>';
                });
            }
            html += '</tbody>';

            var table = document.getElementById('custTable');
            table.innerHTML = html;

            table.querySelectorAll('[data-edit]').forEach(function (b) {
                b.addEventListener('click', function (ev) {
                    ev.stopPropagation();
                    self.openBlade(parseInt(b.getAttribute('data-edit'), 10));
                });
            });
            table.querySelectorAll('[data-del]').forEach(function (b) {
                b.addEventListener('click', function (ev) {
                    ev.stopPropagation();
                    var idx = parseInt(b.getAttribute('data-del'), 10);
                    var e = self.draft().entries[idx];
                    if (e._src && e._src.file && !e._src.added) {
                        // Shown as removed until the export writes its origin file without it
                        e._src.removed = true;
                        e._src.custom = true;
                    } else {
                        // Added in the editor and not in any file yet: nothing to keep
                        self.draft().entries.splice(idx, 1);
                    }
                    self.markDirty();
                    self.renderToolbar(); self.renderTable();
                });
            });
            table.querySelectorAll('[data-restore]').forEach(function (b) {
                b.addEventListener('click', function (ev) {
                    ev.stopPropagation();
                    var e = self.draft().entries[parseInt(b.getAttribute('data-restore'), 10)];
                    e._src.removed = false;
                    self.markDirty();
                    self.renderToolbar(); self.renderTable();
                });
            });
            table.querySelectorAll('tbody tr[data-idx]').forEach(function (tr) {
                if (tr.classList.contains('cust-removed')) return;
                tr.addEventListener('click', function () { self.openBlade(parseInt(tr.getAttribute('data-idx'), 10)); });
            });
        },

        renderFooter: function () {
            var self = this;
            var footer = document.getElementById('custFooter');
            footer.innerHTML =
                '<button class="btn primary" id="custAdd">+ Add entry</button>' +
                '<span style="flex:1;"></span>' +
                '<button class="btn" id="custExport" title="Download one JSON file per origin: the base file and every tagged file">Export JSON</button>' +
                '<button class="btn primary" id="custSave" title="Save the overwrite files to disk (choose Classification/&lt;TenantName&gt;/ in your EntraOps repository)">Save&hellip;</button>';

            document.getElementById('custAdd').addEventListener('click', function () { self.openBlade(-1); });
            document.getElementById('custExport').addEventListener('click', function () { self.exportFile(false); });
            document.getElementById('custSave').addEventListener('click', function () { self.exportFile(true); });
        },

        renderHint: function () {
            var t = TYPES[this.state.type];
            document.getElementById('custHint').innerHTML =
                '<div class="callout-title">How EntraOps consumes ' + esc(t.fileName) + '</div>' + t.hint +
                '<div style="margin-top:8px;">Split the entries into tagged files named <code>' + esc(fileStem(t.fileName)) + '_&lt;Tag&gt;.json</code> (for example <code>' + esc(fileStem(t.fileName)) + '_PAW.json</code>) in the tenant-specific folder: EntraOps loads them in addition to the base file and applies the entries in file name order after it. ' + esc(PRECEDENCE[this.state.type]) + ' ' +
                'The <strong>Origin</strong> column shows <em>Base</em> for entries of the base file and the tag for entries of a tagged file, prefixed with <em>Custom</em> once an entry is added, edited or removed here. Export writes every entry back to its origin file; a new entry goes to the target file chosen in the entry dialog (the base file by default).</div>' +
                '<div style="margin-top:8px;">Every entry requires a <strong>Justification</strong>; entries without one are skipped with a warning. ' +
                '<code>EAMTierLevelTagValue</code> is derived automatically from the tier name on export.</div>';
        },

        // ---- Export / Save ----------------------------------------------------
        // One file per origin: the base file and every tagged file of the draft, each with its
        // remaining entries (an emptied file is written as [] so it replaces the old one).
        exportFile: function (useSavePicker) {
            var self = this;
            var type = this.state.type;
            var d = this.draft();
            var issues = validateEntries(type, d.entries);
            if (issues.length && !window.confirm('The draft has ' + issues.length + ' validation issue(s); EntraOps will skip those entries. Continue anyway?')) return;

            var outputs = draftFiles(type, d).map(function (fileName) {
                var entries = d.entries.filter(function (e) { return !(e._src && e._src.removed) && targetFile(type, e) === fileName; });
                return { fileName: fileName, jsonText: JSON.stringify(serializeEntries(type, entries), null, 2) + '\n' };
            });
            var snapshot = JSON.stringify(outputs);
            clearError('custError');

            function done() {
                d.entries = d.entries.filter(function (e) { return !(e._src && e._src.removed); });
                d.files = outputs.map(function (o) { return o.fileName; });
                d.dirty = false;
                persistDrafts(self.drafts);
                clearError('custError');
                self.renderToolbar(); self.renderTable();
            }

            // A browser can block all but the first download of a click ("download multiple files"),
            // and the page can't tell. With several files the draft stays unsaved (removed entries stay
            // restorable) until the user confirms that every file arrived.
            function downloadAll(reason) {
                outputs.forEach(function (o) { downloadJson(o.fileName, o.jsonText); });
                if (outputs.length === 1) { done(); return; }
                self.showDownloadConfirm(type, outputs, snapshot, done, reason);
            }

            function reportSaveError(err) {
                if (err && err.name === 'AbortError') return; // user cancelled
                if (!err || !err.picked) {
                    // Write access to the chosen location was denied: treated like cancel, nothing was written.
                    if (err && err.name === 'NotAllowedError') {
                        showError('custError', 'Nothing was saved: write access was not granted. Save again and allow editing, or use Export JSON.');
                        return;
                    }
                    // The file pickers aren't available here (e.g. opened from file://): download instead.
                    downloadAll('The save dialog is not available in this browser, so the files were downloaded instead.');
                    return;
                }
                var written = err.written || [];
                var pending = outputs.map(function (o) { return o.fileName; }).filter(function (f) { return written.indexOf(f) === -1; });
                showError('custError', (written.length ? 'Saving stopped after ' + written.length + ' of ' + outputs.length + ' files.' : 'Nothing was saved.') +
                    ' Writing ' + (err.failed || 'a file') + ' failed: ' + (err.message || err.name || err) +
                    (written.length ? '\n\nWritten: ' + written.join(', ') : '') +
                    '\nNot written: ' + pending.join(', ') +
                    '\n\nThe draft is kept with all changes; save again to write every file.');
            }

            if (useSavePicker && outputs.length > 1 && window.showDirectoryPicker) {
                saveAllToDirectory(outputs).then(done, reportSaveError);
            } else if (useSavePicker && outputs.length === 1 && window.showSaveFilePicker) {
                saveWithPicker(outputs[0].fileName, outputs[0].jsonText).then(done, reportSaveError);
            } else {
                downloadAll(useSavePicker ? 'The save dialog is not available in this browser, so the files were downloaded instead.' : '');
            }
        },

        // Confirmation callout after a multi-file download: the draft is finalized only when the user
        // confirms, and only if it didn't change since the download.
        showDownloadConfirm: function (type, outputs, snapshot, done, reason) {
            var self = this;
            var host = document.getElementById('custError');
            if (!host) return;
            host.innerHTML = '<div class="callout" role="status" id="custDownloadConfirm" style="margin-bottom:14px;">' +
                '<div class="callout-title">Confirm the downloaded files</div>' +
                (reason ? '<div style="margin-bottom:6px;">' + esc(reason) + '</div>' : '') +
                outputs.length + ' files were sent to your downloads: ' + esc(outputs.map(function (o) { return o.fileName; }).join(', ')) + '. ' +
                'If your browser asked to allow multiple downloads and you blocked it, only the first file arrived. ' +
                'The draft keeps its unsaved changes (and removed entries stay restorable) until you confirm.' +
                '<div style="margin-top:8px;display:flex;gap:8px;">' +
                '<button type="button" class="btn small primary" id="custDownloadDone">All files arrived</button>' +
                '<button type="button" class="btn small" id="custDownloadAgain">Download again</button>' +
                '<button type="button" class="btn small" id="custDownloadDismiss">Dismiss</button></div></div>';
            document.getElementById('custDownloadDone').addEventListener('click', function () {
                var d = self.drafts[type];
                var current = draftFiles(type, d).map(function (fileName) {
                    var entries = d.entries.filter(function (e) { return !(e._src && e._src.removed) && targetFile(type, e) === fileName; });
                    return { fileName: fileName, jsonText: JSON.stringify(serializeEntries(type, entries), null, 2) + '\n' };
                });
                if (JSON.stringify(current) !== snapshot) {
                    showError('custError', 'The draft changed after the download. Export again to write the current entries.');
                    return;
                }
                done();
            });
            document.getElementById('custDownloadAgain').addEventListener('click', function () {
                outputs.forEach(function (o) { downloadJson(o.fileName, o.jsonText); });
            });
            document.getElementById('custDownloadDismiss').addEventListener('click', function () { host.innerHTML = ''; });
        },

        // ---- Blade (add / edit entry) ------------------------------------------
        openBlade: function (editIndex) {
            var self = this;
            var type = this.state.type;
            var entry = editIndex >= 0
                ? JSON.parse(JSON.stringify(this.draft().entries[editIndex]))
                : normalizeEntry(type, { RbacSystem: TYPES[type].systems[0], EAMTierLevelName: '' });
            this.form = {
                editIndex: editIndex, entry: entry, roleQ: '', actionQ: '', permQ: '', currentTier: null,
                // Edited entries stay in their origin file; new entries go to the base file unless changed
                targetFile: editIndex >= 0 ? targetFile(type, this.draft().entries[editIndex]) : TYPES[type].fileName
            };

            var title = (editIndex >= 0 ? 'Edit' : 'Add') + ' overwrite entry';
            EOCE.app.openDrawer(esc(TYPES[type].title), title, this.bladeHtml());
            this.bindBlade();
        },

        bladeHtml: function () {
            var type = this.state.type;
            var e = this.form.entry;
            var html = '<div class="cust-form">';

            html += '<label class="f-label">RBAC system</label>' +
                '<select class="filter f-input" id="cfSys">' +
                TYPES[type].systems.map(function (s) {
                    return '<option value="' + esc(s) + '"' + (e.RbacSystem === s ? ' selected' : '') + '>' + esc(sysShort(s)) + ' (' + esc(s) + ')</option>';
                }).join('') + '</select>';

            if (type === 'roledef') {
                html += '<div class="section-title">Role definition</div>' +
                    '<p class="muted f-note">Pick a role from the current primary classification source, use an item from your Review list, or enter the role manually. RoleDefinitionId and/or RoleDefinitionName is required.</p>';
                html += '<div class="search" style="min-width:auto;"><span class="search-ico">&#128269;</span>' +
                    '<input id="cfRoleSearch" type="text" placeholder="Search classified roles (current primary source)&hellip;"></div>' +
                    '<div class="cust-pick" id="cfRoleResults"></div>';
                html += '<label class="f-label">RoleDefinitionId</label>' +
                    '<input class="f-input cell-mono" id="cfRoleId" type="text" value="' + esc(e.RoleDefinitionId) + '" placeholder="e.g. 62e90394-69f5-4237-9190-012177145e10">';
                html += '<label class="f-label">RoleDefinitionName</label>' +
                    '<input class="f-input" id="cfRoleName" type="text" value="' + esc(e.RoleDefinitionName) + '" placeholder="e.g. Global Administrator">';
                html += '<div id="cfCurrentTier"></div>';
            } else if (type === 'apipermission') {
                html += '<div class="section-title">API permission</div>' +
                    '<p class="muted f-note">Pick a permission from the API Permissions catalog (Classification_ApiPermissions.json), or enter it manually. PermissionValue is required.</p>';
                html += '<div class="search" style="min-width:auto;"><span class="search-ico">&#128269;</span>' +
                    '<input id="cfPermSearch" type="text" placeholder="Search API permissions&hellip;"></div>' +
                    '<div class="cust-pick" id="cfPermResults"></div>';
                html += '<label class="f-label">PermissionValue</label>' +
                    '<input class="f-input cell-mono" id="cfPermValue" type="text" value="' + esc(e.PermissionValue) + '" placeholder="e.g. User.ReadWrite.All">';
                html += '<label class="f-label">Target App ID <span class="muted">(optional &mdash; leave empty to match the permission in any resource app)</span></label>' +
                    '<input class="f-input cell-mono" id="cfPermAppId" type="text" value="' + esc(e.TargetAppId) + '" placeholder="e.g. 00000003-0000-0000-c000-000000000000 (Microsoft Graph)">';
                html += '<label class="f-label">Permission type <span class="muted">(optional)</span></label>' +
                    '<select class="filter f-input" id="cfPermType">' +
                    ['', 'All', 'Application', 'Delegated'].map(function (v) {
                        return '<option value="' + v + '"' + ((e.PermissionType || '') === v ? ' selected' : '') + '>' + (v || 'Not set (any)') + '</option>';
                    }).join('') + '</select>';
            } else {
                html += '<div class="section-title">Role definition actions</div>' +
                    '<p class="muted f-note">Add role actions from the current primary classification source (tenant-specific template when available, built-in otherwise), from your Review list &mdash; incl. all actions of a starred role &mdash; or manually.</p>';
                html += '<div class="cust-chips" id="cfActionChips"></div>';
                html += '<div class="cust-addrow"><input class="f-input cell-mono" id="cfActionManual" type="text" placeholder="Add action manually, e.g. microsoft.directory/devices/delete">' +
                    '<button class="btn small" id="cfActionManualAdd">Add</button></div>';
                html += '<div class="search" style="min-width:auto;margin-top:10px;"><span class="search-ico">&#128269;</span>' +
                    '<input id="cfActionSearch" type="text" placeholder="Search role actions in the primary source&hellip;"></div>' +
                    '<div class="muted f-note" id="cfActionSourceNote"></div>' +
                    '<div class="cust-pick" id="cfActionResults"></div>';
                html += '<label class="f-label">Role assignment scope(s) <span class="muted">(comma separated, wildcards allowed)</span></label>' +
                    '<input class="f-input cell-mono" id="cfScopes" type="text" value="' + esc((e.RoleAssignmentScopeName || []).join(', ')) + '" placeholder="/*">';
            }

            html += '<div class="section-title">&#9733; From your Review list</div><div id="cfReview"></div>';

            html += '<div class="section-title">New classification</div>';
            html += '<label class="f-label">Tier level (EAMTierLevelName)</label>' +
                '<select class="filter f-input" id="cfTier"><option value=""' + (e.EAMTierLevelName ? '' : ' selected') + ' disabled>Select tier&hellip;</option>' +
                TIER_CHOICES.map(function (t) {
                    var tier = EOCE.tier(t);
                    return '<option value="' + t + '"' + (e.EAMTierLevelName === t ? ' selected' : '') + '>' + esc(tier.label) + ' (Tier ' + tier.tag + ')</option>';
                }).join('') + '</select>';
            html += '<div id="cfTierChange"></div>';
            html += '<label class="f-label">' + (type === 'apipermission' ? 'Category' : 'Service') + ' <span class="muted">(optional, shown as classification ' + (type === 'apipermission' ? 'category' : 'service') + ')</span></label>' +
                '<input class="f-input" id="cfService" type="text" value="' + esc(e.Service) + '" placeholder="e.g. Device Management">';
            html += '<label class="f-label">Justification <span class="chip attack" style="font-size:10px;">required</span></label>' +
                '<textarea class="f-input" id="cfJust" rows="3" placeholder="Document why this classification is changed, e.g. \'No privileged access workstation is present in the tenant.\'">' + esc(e.Justification) + '</textarea>';

            var draft = this.draft();
            var files = draftFiles(type, draft);
            if (files.indexOf(this.form.targetFile) === -1) files.push(this.form.targetFile);
            html += '<label class="f-label">Target file <span class="muted">(the entry is written to this file on export)</span></label>' +
                '<select class="f-input" id="cfTarget">' +
                files.map(function (f) {
                    return '<option value="' + esc(f) + '"' + (f === this.form.targetFile ? ' selected' : '') + '>' + esc(fileLabel(type, draft, f) + ' \u2013 ' + f) + '</option>';
                }, this).join('') +
                '<option value="__new">New tagged file&hellip;</option></select>' +
                '<input class="f-input" id="cfNewTag" type="text" hidden placeholder="Tag, e.g. PAW (creates ' + esc(fileStem(TYPES[type].fileName)) + '_PAW.json)">';

            html += '<div id="cfError"></div>';
            html += '<div class="cust-blade-foot">' +
                '<button class="btn primary" id="cfApply">' + (this.form.editIndex >= 0 ? 'Update entry' : 'Add to file') + '</button>' +
                '<button class="btn" id="cfCancel">Cancel</button></div>';
            html += '</div>';
            return html;
        },

        bindBlade: function () {
            var self = this;
            var type = this.state.type;
            var e = this.form.entry;

            document.getElementById('cfSys').addEventListener('change', function (ev) {
                e.RbacSystem = ev.target.value;
                if (type === 'roledef') self.renderRoleResults();
                else if (type === 'roleaction') self.renderActionResults();
                self.renderReviewSection();
            });
            document.getElementById('cfTier').addEventListener('change', function (ev) {
                e.EAMTierLevelName = ev.target.value;
                self.updateTierChange();
            });
            document.getElementById('cfService').addEventListener('input', function (ev) { e.Service = ev.target.value.trim(); });
            document.getElementById('cfJust').addEventListener('input', function (ev) { e.Justification = ev.target.value.trim(); });
            document.getElementById('cfTarget').addEventListener('change', function (ev) {
                var isNew = ev.target.value === '__new';
                document.getElementById('cfNewTag').hidden = !isNew;
                if (isNew) document.getElementById('cfNewTag').focus();
                else self.form.targetFile = ev.target.value;
            });

            if (type === 'roledef') {
                document.getElementById('cfRoleId').addEventListener('input', function (ev) { e.RoleDefinitionId = ev.target.value.trim(); });
                document.getElementById('cfRoleName').addEventListener('input', function (ev) { e.RoleDefinitionName = ev.target.value.trim(); });
                document.getElementById('cfRoleSearch').addEventListener('input', EOCE.util.debounce(function (ev) {
                    self.form.roleQ = ev.target.value.trim().toLowerCase();
                    self.renderRoleResults();
                }, 150));
                this.renderRoleResults();
                // When editing an existing entry, resolve the current classification
                // of the referenced role so the down-/upgrade indicator works immediately.
                if (e.RoleDefinitionId || e.RoleDefinitionName) {
                    loadRolesIndex().then(function (idx) {
                        var role = idx.byId[e.RbacSystem + '|' + e.RoleDefinitionId];
                        if (!role && e.RoleDefinitionName) {
                            role = idx.list.filter(function (r) {
                                return r.sysKey === e.RbacSystem && r.name.toLowerCase() === e.RoleDefinitionName.toLowerCase();
                            })[0];
                        }
                        if (role) {
                            self.form.currentTier = role.tier;
                            var cur = document.getElementById('cfCurrentTier');
                            if (cur) cur.innerHTML = '<div class="f-note" style="margin-top:6px;">Current classification: ' + EOCE.util.tierBadge(role.tier, { short: true }) + '</div>';
                            self.updateTierChange();
                        }
                    });
                }
            } else if (type === 'apipermission') {
                document.getElementById('cfPermValue').addEventListener('input', function (ev) { e.PermissionValue = ev.target.value.trim(); });
                document.getElementById('cfPermAppId').addEventListener('input', function (ev) { e.TargetAppId = ev.target.value.trim(); });
                document.getElementById('cfPermType').addEventListener('change', function (ev) { e.PermissionType = ev.target.value; });
                document.getElementById('cfPermSearch').addEventListener('input', EOCE.util.debounce(function (ev) {
                    self.form.permQ = ev.target.value.trim().toLowerCase();
                    self.renderPermissionResults();
                }, 150));
                this.renderPermissionResults();
            } else {
                document.getElementById('cfScopes').addEventListener('input', function (ev) {
                    e.RoleAssignmentScopeName = ev.target.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
                });
                document.getElementById('cfActionManualAdd').addEventListener('click', function () {
                    var inp = document.getElementById('cfActionManual');
                    var val = inp.value.trim();
                    if (val) { self.addAction(val); inp.value = ''; }
                });
                document.getElementById('cfActionManual').addEventListener('keydown', function (ev) {
                    if (ev.key === 'Enter') { ev.preventDefault(); document.getElementById('cfActionManualAdd').click(); }
                });
                document.getElementById('cfActionSearch').addEventListener('input', EOCE.util.debounce(function (ev) {
                    self.form.actionQ = ev.target.value.trim().toLowerCase();
                    self.renderActionResults(true);
                }, 150));
                this.renderActionChips();
                this.renderActionResults();
            }

            this.renderReviewSection();
            this.updateTierChange();

            document.getElementById('cfApply').addEventListener('click', function () { self.applyBlade(); });
            document.getElementById('cfCancel').addEventListener('click', function () { EOCE.app.closeDrawer(); });
        },

        applyBlade: function () {
            var type = this.state.type;
            var e = this.form.entry;
            var problems = [];
            if (type === 'roledef' && !e.RoleDefinitionId && !e.RoleDefinitionName) problems.push('RoleDefinitionId or RoleDefinitionName is required.');
            if (type === 'roleaction' && !e.RoleDefinitionActions.length) problems.push('At least one role definition action is required.');
            if (type === 'apipermission' && !e.PermissionValue) problems.push('PermissionValue is required.');
            if (TIER_CHOICES.indexOf(e.EAMTierLevelName) === -1) problems.push('Select a tier level.');
            if (!e.Justification) problems.push('A Justification is mandatory.');
            var target = this.form.targetFile;
            var targetSelect = document.getElementById('cfTarget');
            if (targetSelect && targetSelect.value === '__new') {
                var newTag = document.getElementById('cfNewTag').value.trim();
                if (!/^[A-Za-z0-9-]+(_[A-Za-z0-9-]+)*$/.test(newTag)) problems.push('Enter a tag of letters, digits, "-" or "_" for the new tagged file.');
                else target = resolveFileName(draftFiles(type, this.draft()), fileStem(TYPES[type].fileName) + '_' + newTag + '.json');
            }
            if (problems.length) { showError('cfError', 'Please fix before applying:\n\n- ' + problems.join('\n- ')); return; }

            if (type === 'roleaction' && !e.RoleAssignmentScopeName.length) e.RoleAssignmentScopeName = ['/*'];
            var original = this.form.editIndex >= 0 ? this.draft().entries[this.form.editIndex] : null;
            var parsedTarget = parseOverwriteFileName(target);
            e._src = { file: target, tag: parsedTarget ? parsedTarget.tag : null, custom: true, removed: false, added: !(original && original._src && !original._src.added) };
            if (original && original._src && !original._src.added && original._src.file !== target) {
                // Moved to another file: the origin file is still written, without the entry
                if (this.draft().files.indexOf(original._src.file) === -1) this.draft().files.push(original._src.file);
            }
            if (this.form.editIndex >= 0) this.draft().entries[this.form.editIndex] = e;
            else this.draft().entries.push(e);
            this.markDirty();
            EOCE.app.closeDrawer();
            this.renderToolbar(); this.renderTable();
        },

        // ---- Role picker (roledef) ----------------------------------------------
        renderRoleResults: function () {
            var self = this;
            var box = document.getElementById('cfRoleResults');
            if (!box) return;
            box.innerHTML = '<div class="muted f-note">Loading roles&hellip;</div>';
            loadRolesIndex().then(function (idx) {
                if (!document.getElementById('cfRoleResults')) return;
                var q = self.form.roleQ;
                var sys = self.form.entry.RbacSystem;
                var matches = idx.list.filter(function (r) {
                    if (r.sysKey !== sys) return false;
                    if (q && r.name.toLowerCase().indexOf(q) === -1 && r.id.toLowerCase().indexOf(q) === -1) return false;
                    return true;
                }).slice(0, 25);
                if (!matches.length) {
                    box.innerHTML = '<div class="muted f-note">No classified roles match' + (q ? ' "' + esc(q) + '"' : '') + ' for ' + esc(sysShort(sys)) + '. Defender has no per-role export &mdash; enter the role manually.</div>';
                    return;
                }
                box.innerHTML = matches.map(function (r, i) {
                    return '<div class="action-row cust-pick-row" data-pick="' + i + '" style="cursor:pointer;">' +
                        '<div style="min-width:0;"><div class="a-name">' + esc(r.name) + '</div>' +
                        '<div class="a-cat cell-mono">' + esc(r.id) + '</div></div>' +
                        EOCE.util.tierBadge(r.tier, { short: true }) + '</div>';
                }).join('');
                box.querySelectorAll('[data-pick]').forEach(function (row) {
                    row.addEventListener('click', function () {
                        var r = matches[parseInt(row.getAttribute('data-pick'), 10)];
                        self.selectRole(r);
                    });
                });
            });
        },

        selectRole: function (r) {
            var e = this.form.entry;
            e.RoleDefinitionId = r.id;
            e.RoleDefinitionName = r.name;
            this.form.currentTier = r.tier;
            var idEl = document.getElementById('cfRoleId');
            var nameEl = document.getElementById('cfRoleName');
            if (idEl) idEl.value = r.id;
            if (nameEl) nameEl.value = r.name;
            var cur = document.getElementById('cfCurrentTier');
            if (cur) {
                cur.innerHTML = '<div class="f-note" style="margin-top:6px;">Current classification: ' + EOCE.util.tierBadge(r.tier, { short: true }) + '</div>';
            }
            this.updateTierChange();
        },

        updateTierChange: function () {
            var box = document.getElementById('cfTierChange');
            if (!box) return;
            var cur = this.form.currentTier;
            var next = this.form.entry.EAMTierLevelName;
            if (!cur || TIER_CHOICES.indexOf(next) === -1) { box.innerHTML = ''; return; }
            var curTag = parseInt(EOCE.tier(cur).tag, 10);
            var nextTag = parseInt(EOCE.tier(next).tag, 10);
            var label, cls;
            if (isNaN(curTag) || isNaN(nextTag) || curTag === nextTag) { label = 'No tier change'; cls = ''; }
            else if (nextTag > curTag) { label = '&#8595; Downgrade (less privileged)'; cls = 'scope'; }
            else { label = '&#8593; Upgrade (more privileged)'; cls = 'warn'; }
            box.innerHTML = '<div class="f-note" style="margin-top:6px;">' + EOCE.util.tierBadge(cur, { short: true }) + ' &rarr; ' + EOCE.util.tierBadge(next, { short: true }) + ' <span class="chip ' + cls + '">' + label + '</span></div>';
        },

        // ---- Action picker (roleaction) ---------------------------------------------
        addAction: function (action) {
            var e = this.form.entry;
            var exists = e.RoleDefinitionActions.some(function (a) { return a.toLowerCase() === action.toLowerCase(); });
            if (!exists) e.RoleDefinitionActions.push(action);
            this.renderActionChips();
        },

        renderActionChips: function () {
            var self = this;
            var box = document.getElementById('cfActionChips');
            if (!box) return;
            var acts = this.form.entry.RoleDefinitionActions;
            if (!acts.length) {
                box.innerHTML = '<div class="muted f-note">No actions added yet.</div>';
                return;
            }
            box.innerHTML = acts.map(function (a, i) {
                return '<span class="chip cust-chip cell-mono">' + esc(a) + '<button type="button" class="cust-chip-x" data-rm="' + i + '" title="Remove">&#10005;</button></span>';
            }).join('');
            box.querySelectorAll('[data-rm]').forEach(function (b) {
                b.addEventListener('click', function () {
                    self.form.entry.RoleDefinitionActions.splice(parseInt(b.getAttribute('data-rm'), 10), 1);
                    self.renderActionChips();
                });
            });
        },

        renderActionResults: function (keepNote) {
            var self = this;
            var box = document.getElementById('cfActionResults');
            var note = document.getElementById('cfActionSourceNote');
            if (!box) return;
            var sys = this.form.entry.RbacSystem;
            var tpl = DEFINITION_FILES[sys];
            if (!tpl) { box.innerHTML = ''; if (note) note.textContent = ''; return; }
            var path = primaryPath(tpl);
            if (note && !keepNote) note.innerHTML = 'Primary source: <span class="cell-mono">' + esc(path.split('/').pop()) + '</span> &middot; ' + esc(sourceLabelForPath(path));
            box.innerHTML = '<div class="muted f-note">Loading actions&hellip;</div>';
            EOCE.data.loadRaw(path).catch(function () {
                // Fall back to the built-in template when the tenant copy cannot be loaded.
                return path === tpl ? [] : EOCE.data.loadRaw(tpl).catch(function () { return []; });
            }).then(function (def) {
                if (!document.getElementById('cfActionResults')) return;
                var q = self.form.actionQ;
                var all = flattenDefinition(def);
                if (!all.length) {
                    box.innerHTML = '<div class="muted f-note">No classification definition available for ' + esc(sysShort(sys)) + ' (source not embedded / reachable). Add actions manually or via the Review list.</div>';
                    return;
                }
                var matches = all.filter(function (a) {
                    return !q || a.action.toLowerCase().indexOf(q) !== -1 || (a.service || '').toLowerCase().indexOf(q) !== -1;
                }).slice(0, 25);
                if (!matches.length) { box.innerHTML = '<div class="muted f-note">No actions match "' + esc(q) + '".</div>'; return; }
                box.innerHTML = matches.map(function (a, i) {
                    return '<div class="action-row cust-pick-row" data-pick="' + i + '" style="cursor:pointer;">' +
                        '<div style="min-width:0;"><div class="a-name">' + esc(a.action) + '</div>' +
                        (a.service ? '<div class="a-cat">' + esc(a.service) + '</div>' : '') + '</div>' +
                        EOCE.util.tierBadge(a.tier, { short: true }) + '</div>';
                }).join('');
                box.querySelectorAll('[data-pick]').forEach(function (row) {
                    row.addEventListener('click', function () {
                        var a = matches[parseInt(row.getAttribute('data-pick'), 10)];
                        self.addAction(a.action);
                    });
                });
            });
        },

        // ---- Permission picker (apipermission) ---------------------------------
        renderPermissionResults: function () {
            var self = this;
            var box = document.getElementById('cfPermResults');
            if (!box) return;
            box.innerHTML = '<div class="muted f-note">Loading permissions&hellip;</div>';
            EOCE.data.load(PERMISSION_CATALOG_FILE).catch(function () { return []; }).then(function (all) {
                if (!document.getElementById('cfPermResults')) return;
                var q = self.form.permQ;
                var matches = (all || []).filter(function (p) {
                    if (!q) return true;
                    return String(p.PermissionValue || '').toLowerCase().indexOf(q) !== -1 ||
                        String(p.TargetAppDisplayName || '').toLowerCase().indexOf(q) !== -1 ||
                        String(p.Category || '').toLowerCase().indexOf(q) !== -1;
                }).slice(0, 25);
                if (!all.length) {
                    box.innerHTML = '<div class="muted f-note">API permission catalog not embedded / reachable. Add the permission manually.</div>';
                    return;
                }
                if (!matches.length) { box.innerHTML = '<div class="muted f-note">No permissions match "' + esc(q) + '".</div>'; return; }
                box.innerHTML = matches.map(function (p, i) {
                    return '<div class="action-row cust-pick-row" data-pick="' + i + '" style="cursor:pointer;">' +
                        '<div style="min-width:0;"><div class="a-name">' + esc(p.PermissionValue) + '</div>' +
                        '<div class="a-cat">' + esc(p.TargetAppDisplayName || '') + (p.PermissionType ? ' &middot; ' + esc(p.PermissionType) : '') + '</div></div>' +
                        (p.EAMTierLevelName ? EOCE.util.tierBadge(p.EAMTierLevelName, { short: true }) : '') + '</div>';
                }).join('');
                box.querySelectorAll('[data-pick]').forEach(function (row) {
                    row.addEventListener('click', function () {
                        self.selectPermission(matches[parseInt(row.getAttribute('data-pick'), 10)]);
                    });
                });
            });
        },

        selectPermission: function (p) {
            var e = this.form.entry;
            e.PermissionValue = p.PermissionValue || '';
            e.TargetAppId = p.TargetAppId || '';
            e.PermissionType = ['Application', 'Delegated'].indexOf(p.PermissionType) !== -1 ? p.PermissionType : '';
            var valEl = document.getElementById('cfPermValue');
            var appEl = document.getElementById('cfPermAppId');
            var typeEl = document.getElementById('cfPermType');
            if (valEl) valEl.value = e.PermissionValue;
            if (appEl) appEl.value = e.TargetAppId;
            if (typeEl) typeEl.value = e.PermissionType;
        },

        // ---- Review list section --------------------------------------------------
        renderReviewSection: function () {
            var self = this;
            var box = document.getElementById('cfReview');
            if (!box) return;
            var type = this.state.type;
            if (type === 'apipermission') {
                box.innerHTML = '<div class="muted f-note">Review-list linking is not yet available for API permissions &mdash; use the picker above or enter the permission manually.</div>';
                return;
            }
            var items = reviewItems().map(function (it) {
                return { item: it, res: resolveReviewItem(it) };
            }).filter(function (x) {
                if (!x.res) return false;
                if (type === 'roledef') return x.res.kind === 'role';
                return true; // role actions AND roles (add all actions of a role)
            });

            if (!items.length) {
                box.innerHTML = '<div class="muted f-note">No matching items on your Review list. Star roles' + (type === 'roleaction' ? ' or role actions' : '') + ' anywhere in the reporting apps to reuse them here.</div>';
                return;
            }

            box.innerHTML = items.map(function (x, i) {
                var it = x.item, res = x.res;
                var btn;
                if (type === 'roledef') {
                    btn = '<button class="btn small" data-rv="' + i + '">Use role</button>';
                } else if (res.kind === 'action') {
                    btn = '<button class="btn small" data-rv="' + i + '">Add action</button>';
                } else {
                    btn = '<button class="btn small" data-rv="' + i + '" title="Add every role action of this role\'s definition">Add all role actions</button>';
                }
                return '<div class="action-row" style="cursor:default;">' +
                    '<div style="min-width:0;"><div class="a-name">' + esc(it.name) + '</div>' +
                    '<div class="a-cat">' + esc(it.kind) + (it.system ? ' &middot; ' + esc(it.system) : '') + (it.tier ? '' : '') + '</div></div>' +
                    (it.tier ? EOCE.util.tierBadge(it.tier, { short: true }) : '') + btn + '</div>';
            }).join('');

            box.querySelectorAll('[data-rv]').forEach(function (b) {
                b.addEventListener('click', function () {
                    self.useReviewItem(items[parseInt(b.getAttribute('data-rv'), 10)]);
                });
            });
        },

        useReviewItem: function (x) {
            var self = this;
            var type = this.state.type;
            var res = x.res, item = x.item;
            var e = this.form.entry;

            if (type === 'roledef') {
                loadRolesIndex().then(function (idx) {
                    var role = (res.sysKey && res.roleId) ? idx.byId[res.sysKey + '|' + res.roleId] : null;
                    if (!role) {
                        // Fallback: match by role name across supported systems.
                        role = idx.list.filter(function (r) { return r.name.toLowerCase() === String(item.name).toLowerCase(); })[0];
                    }
                    if (role) {
                        if (TYPES.roledef.systems.indexOf(role.sysKey) !== -1 && e.RbacSystem !== role.sysKey) {
                            e.RbacSystem = role.sysKey;
                            var sysEl = document.getElementById('cfSys');
                            if (sysEl) sysEl.value = role.sysKey;
                        }
                        self.selectRole(role);
                    } else {
                        e.RoleDefinitionName = item.name;
                        var nameEl = document.getElementById('cfRoleName');
                        if (nameEl) nameEl.value = item.name;
                    }
                });
                return;
            }

            // roleaction mode
            if (res.kind === 'action') {
                if (res.sysKey && TYPES.roleaction.systems.indexOf(res.sysKey) !== -1 && e.RbacSystem !== res.sysKey) {
                    e.RbacSystem = res.sysKey;
                    var sysEl = document.getElementById('cfSys');
                    if (sysEl) sysEl.value = res.sysKey;
                    this.renderActionResults();
                }
                this.addAction(res.action);
                return;
            }

            // Role on the review list: add ALL role actions of its role definition.
            loadRolesIndex().then(function (idx) {
                var role = (res.sysKey && res.roleId) ? idx.byId[res.sysKey + '|' + res.roleId] : null;
                if (!role) role = idx.list.filter(function (r) { return r.name.toLowerCase() === String(item.name).toLowerCase(); })[0];
                if (!role) { showError('cfError', 'Could not resolve the role definition for "' + item.name + '" in the classified role exports.'); return; }
                if (!role.actions.length) { showError('cfError', 'The role "' + role.name + '" has no role actions in its definition.'); return; }
                if (TYPES.roleaction.systems.indexOf(role.sysKey) !== -1 && e.RbacSystem !== role.sysKey) {
                    e.RbacSystem = role.sysKey;
                    var sysEl = document.getElementById('cfSys');
                    if (sysEl) sysEl.value = role.sysKey;
                    self.renderActionResults();
                }
                role.actions.forEach(function (a) { self.addAction(a); });
            });
        }
    };

    return view;
})();
