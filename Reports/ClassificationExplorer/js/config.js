/*
 * EntraOps Classification Explorer - Configuration
 * Central metadata: data sources, Enterprise Access Model tiers,
 * RBAC systems and reference documentation links.
 */
window.EOCE = window.EOCE || {};

// --- Deployment mode -------------------------------------------------------
// This app source is shared, byte-identical, between two deployments:
//   'standalone' (default) - the AzurePrivilegedIAM repository, a single flat
//                 set of classification-logic templates (EntraOps_Classification/),
//                 no tenant variants, and the (standalone-only) Change History view.
//   'entraops'  - embedded in the EntraOps repository/portal: adds multi-tenant
//                 classification variants (Classification/Templates + tenant-specific
//                 Classification/<TenantName> copies), the Customize Overwrites /
//                 Template Comparison views, and cross-app portal navigation.
// The mode is set by js/mode.js, a single small file that is NOT synced between
// the two copies (see Scripts/Sync-EntraOpsClassificationExplorerSource.ps1) - everything
// else in this app is generated from one source and kept identical.
EOCE.MODE = (window.EOCE_MODE === 'entraops') ? 'entraops' : 'standalone';
EOCE.isEntraOpsMode = function () { return EOCE.MODE === 'entraops'; };
EOCE.GENERATOR_COMMAND = EOCE.isEntraOpsMode()
    ? 'Import-Module ./EntraOps -Force; Update-EntraOpsClassificationExplorerData -Mode EntraOps'
    : '. ./Scripts/Update-EntraOpsClassificationExplorerData.ps1; Update-EntraOpsClassificationExplorerData -Mode Standalone';

// The generator stamps its mode into the embedded bundle. Keep this separate from
// EOCE.MODE so app startup can reject a stale or incorrectly deployed bundle.
EOCE.BUNDLE_MODE = window.EOCE_DATA_MANIFEST && typeof window.EOCE_DATA_MANIFEST.mode === 'string'
    ? window.EOCE_DATA_MANIFEST.mode.toLowerCase()
    : '';
EOCE.deploymentError = EOCE.BUNDLE_MODE && EOCE.BUNDLE_MODE !== EOCE.MODE
    ? 'Deployment mode mismatch: js/mode.js declares "' + EOCE.MODE +
    '", but data/classification-data.js was generated for "' + EOCE.BUNDLE_MODE +
    '". Regenerate the bundle with the matching -Mode.'
    : null;

// Base folder for classification-logic definition/param templates. Basenames are
// identical between the two repositories, only the containing folder differs:
//   standalone - EntraOps_Classification/Classification_AadResources.json
//   entraops   - Classification/Templates/Classification_AadResources.json
EOCE.TEMPLATE_BASE = EOCE.isEntraOpsMode() ? 'Classification/Templates' : 'EntraOps_Classification';
EOCE.templateFile = function (name) { return EOCE.TEMPLATE_BASE + '/' + name; };

// --- Portal-wide navigation (entraops mode only) ---------------------------
// When embedded in the EntraOps reporting portal, sibling apps live in sibling
// folders under Reports/. Rendered client-side by js/app.js (renderPortalNav)
// so index.html stays byte-identical between the standalone and entraops copies.
EOCE.PORTAL_NAV_LABEL = 'Privileged EAM Reporting';
EOCE.PORTAL_NAV = EOCE.isEntraOpsMode() ? [
    { label: 'Home', href: '../index.html', icon: '&#8962;' },
    { label: 'Classification Explorer', current: true, icon: '&#9737;' },
    { label: 'EAM Dashboard', href: '../EamDashboard/index.html', icon: '&#9635;' },
    { label: 'Privileged Assets', href: '../PrivilegedAssets/index.html', icon: '&#9776;' },
    { label: 'Access Path Map', href: '../AccessPathMap/index.html', icon: '&#10565;' },
    { label: 'Tier Breach Analyzer', href: '../TierBreachAnalyzer/index.html', icon: '&#9888;' },
    { label: 'Privilege History', href: '../PrivilegeHistory/index.html', icon: '&#8635;' }
] : [];

// --- Classification source variants (entraops mode only) ------------------
// The classification-logic files ship as built-in templates under
// Classification/Templates. Running Update-EntraOpsClassificationControlPlaneScope
// writes a tenant-specific, parameterized copy to Classification/<TenantName>.
// New-EntraOpsClassificationExplorerData discovers those folders and embeds them as
// window.EOCE_TENANTS; the variant selector in the app bar switches which set
// is displayed, and the Template Comparison view diffs the two. Not applicable
// in standalone mode (no tenant-specific copies exist there), so every helper
// below is a no-op unless EOCE.isEntraOpsMode() is true.
EOCE.TENANTS = (EOCE.isEntraOpsMode() && Array.isArray(window.EOCE_TENANTS)) ? window.EOCE_TENANTS : [];
EOCE.VARIANT_TEMPLATE = 'template';
EOCE._variant = null;

EOCE.variantOptions = function () {
    if (!EOCE.isEntraOpsMode()) return [];
    var opts = [{ key: EOCE.VARIANT_TEMPLATE, label: 'Built-in template' }];
    EOCE.TENANTS.forEach(function (t) {
        if (t && t.name) opts.push({ key: t.name, label: t.name });
    });
    return opts;
};

EOCE.tenantByName = function (name) {
    for (var i = 0; i < EOCE.TENANTS.length; i++) {
        if (EOCE.TENANTS[i] && EOCE.TENANTS[i].name === name) return EOCE.TENANTS[i];
    }
    return null;
};

EOCE.getVariant = function () {
    if (!EOCE.isEntraOpsMode()) return EOCE.VARIANT_TEMPLATE;
    if (EOCE._variant === null) {
        var stored = null;
        try { stored = window.localStorage.getItem('eoce.variant'); } catch (e) { /* private mode */ }
        var valid = EOCE.variantOptions().some(function (o) { return o.key === stored; });
        EOCE._variant = valid ? stored : EOCE.VARIANT_TEMPLATE;
    }
    return EOCE._variant;
};

EOCE.setVariant = function (key) {
    if (!EOCE.isEntraOpsMode()) return EOCE.VARIANT_TEMPLATE;
    var valid = EOCE.variantOptions().some(function (o) { return o.key === key; });
    EOCE._variant = valid ? key : EOCE.VARIANT_TEMPLATE;
    try { window.localStorage.setItem('eoce.variant', EOCE._variant); } catch (e) { /* private mode */ }
    return EOCE._variant;
};

// Map a built-in template path to the tenant-specific copy when the tenant has
// one. *.Param.json files are template-only concepts (they carry the scope
// placeholders), so they are never remapped. Returns null when no tenant copy
// exists for the file.
EOCE.tenantFileFor = function (tenantName, templatePath) {
    var tenant = EOCE.tenantByName(tenantName);
    if (!tenant || !templatePath) return null;
    if (templatePath.indexOf('Classification/Templates/') !== 0) return null;
    if (/\.Param\.json$/i.test(templatePath)) return null;
    var candidate = 'Classification/' + tenantName + '/' + templatePath.split('/').pop();
    return (tenant.files || []).indexOf(candidate) !== -1 ? candidate : null;
};

// Resolve a data path according to the active variant: tenant-specific copy
// when one exists, built-in template otherwise. No-op outside entraops mode.
EOCE.resolveDataPath = function (path) {
    if (!EOCE.isEntraOpsMode()) return path;
    var variant = EOCE.getVariant();
    if (variant === EOCE.VARIANT_TEMPLATE) return path;
    return EOCE.tenantFileFor(variant, path) || path;
};

// --- Enterprise Access Model tier levels --------------------------------
// Tag values follow EntraOps: 0 = Control Plane, 1 = Management Plane,
// 2 = User Access. "Unclassified" is used where no classification matched.
EOCE.TIERS = {
    ControlPlane: {
        key: 'ControlPlane',
        tag: '0',
        label: 'Control Plane',
        short: 'Control',
        color: '#a4262c',
        bg: 'rgba(164, 38, 44, 0.10)',
        border: 'rgba(164, 38, 44, 0.35)',
        description:
            'Highest-impact access. Controls identities, security configuration and the trust fabric itself (for example role and policy management, credential and authentication management, directory synchronization). Compromise here leads to full tenant or estate takeover.',
        examples: 'Role assignment, credential reset for admins, Conditional Access policy, federation/sync configuration.'
    },
    ManagementPlane: {
        key: 'ManagementPlane',
        tag: '1',
        label: 'Management Plane',
        short: 'Management',
        color: '#c07807',
        bg: 'rgba(192, 120, 7, 0.10)',
        border: 'rgba(192, 120, 7, 0.35)',
        description:
            'Workload and service management. Manages applications, devices, groups and resources but does not control the security/identity fabric directly. Strict separation from the Control Plane avoids full tenant compromise if a Management Plane principal is breached.',
        examples: 'App configuration, group membership, device management, resource provisioning.'
    },
    UserAccess: {
        key: 'UserAccess',
        tag: '2',
        label: 'User Access',
        short: 'User',
        color: '#0e700e',
        bg: 'rgba(14, 112, 14, 0.10)',
        border: 'rgba(14, 112, 14, 0.35)',
        description:
            'Read-oriented or self-service level access with limited blast radius. Typically reader permissions or actions scoped to the principal\'s own objects.',
        examples: 'Reading directory data, viewing reports, self-service profile read.'
    },
    Unclassified: {
        key: 'Unclassified',
        tag: 'Unclassified',
        label: 'Unclassified',
        short: 'Unclassified',
        color: '#605e5c',
        bg: 'rgba(96, 94, 92, 0.10)',
        border: 'rgba(96, 94, 92, 0.30)',
        description:
            'No classification has been matched yet for this role action or permission. These are candidates for community contribution and review.',
        examples: 'New or niche role actions not yet mapped to a tier.'
    }
};

EOCE.TIER_ORDER = ['ControlPlane', 'ManagementPlane', 'UserAccess', 'Unclassified'];

EOCE.tier = function (name) {
    return EOCE.TIERS[name] || EOCE.TIERS.Unclassified;
};

// --- RBAC systems --------------------------------------------------------
// Each "roles" system has a generated output file (classified roles with their
// role actions). Definition/Param files drive the classification logic.
EOCE.RBAC_SYSTEMS = {
    EntraID: {
        key: 'EntraID',
        name: 'Microsoft Entra ID Directory Roles',
        short: 'Entra ID',
        icon: 'entra',
        kind: 'roles',
        file: 'Classification/Classification_EntraIdDirectoryRoles.json',
        definition: EOCE.templateFile('Classification_AadResources.json'),
        param: EOCE.templateFile('Classification_AadResources.Param.json'),
        actionLabel: 'Role action',
        description:
            'Built-in Microsoft Entra ID directory roles and their role actions (microsoft.directory/*), classified against the Enterprise Access Model.',
        docs: 'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference',
        // Some directory role actions (e.g. administrative-unit scoped user/credential
        // management) resolve to a different plane depending on whether the assignment
        // scope targets privileged objects. See EOCE.SCOPE_PARAM_SYSTEMS / the
        // Scope-aware Tiering page for how this is resolved from Classification_AadResources.Param.json.
        scopeAware: {
            label: 'Placeholder-based dynamic tiering',
            summary: 'Some Microsoft Entra ID directory role actions resolve to a different Enterprise Access Model plane depending on whether their assignment scope (for example an administrative unit) targets privileged objects. EntraOps resolves this dynamically from scope placeholders rather than from the role action alone.',
            docsLabel: 'Scope-aware Tiering page',
            docs: '#scoped'
        }
    },
    IdentityGovernance: {
        key: 'IdentityGovernance',
        name: 'Microsoft Entra Identity Governance (Entitlement Management)',
        short: 'ID Governance',
        icon: 'identitygovernance',
        kind: 'roles',
        file: 'Classification/Classification_IdentityGovernance.json',
        definition: EOCE.templateFile('Classification_IdentityGovernance.json'),
        param: EOCE.templateFile('Classification_IdentityGovernance.Param.json'),
        actionLabel: 'Role action',
        description:
            'Microsoft Entra Identity Governance / Entitlement Management roles (microsoft.entitlementManagement/*) for delegated access-package and catalog administration, classified against the Enterprise Access Model.',
        docs: 'https://learn.microsoft.com/entra/id-governance/entitlement-management-delegate',
        // Entitlement Management roles are delegated per access-package catalog, so their
        // Enterprise Access Model plane is resolved dynamically from the assignment scope
        // (the catalog and what it contains) rather than from the role actions alone.
        // See EntraOps "Classification of Identity Governance delegation and roles".
        scopeAware: {
            label: 'Catalog-scoped dynamic tiering',
            summary: 'Identity Governance roles are delegated per access-package catalog, so the same role can land on a different Enterprise Access Model plane depending on what the catalog contains. EntraOps resolves this dynamically from the assignment scope, not from the role actions alone.',
            // Unlike the other RBAC systems (where only specific placeholder-tagged actions
            // are scope-aware), every Identity Governance role/action is catalog-scoped -
            // see EOCE.isFullyScopeAwareSystem.
            allActionsScopeAware: true,
            methods: [
                {
                    tag: 'JSONwithAction',
                    text: 'Scope and role actions are tagged manually in the EntraOps Classification_IdentityGovernance.json template (scope /AccessPackageCatalog/*), giving each Entitlement Management action a tier and service. This is the classification shown here.'
                },
                {
                    tag: 'AssignedAadGroup',
                    text: 'At runtime EntraOps reads the resources assigned inside a catalog (for example a role-assignable or privileged group) and applies their classification to any delegation scoped to that catalog. Concrete Assigned* provenance tags identify whether the resource is an Entra group, application permission, directory role, or Azure resource. A Catalog owner over a catalog that grants Tier 0 access therefore becomes Control Plane automatically. Because catalogs are objects a delegated admin can create at any time, this resolution fails safe: a catalog only leaves Control Plane once it is affirmatively proven to be Management Plane or User Access - anything unresolved, unclassified or newly created between classification runs stays Control Plane by default.'
                }
            ],
            docsLabel: 'Entitlement Management delegation reference',
            docs: 'https://learn.microsoft.com/entra/id-governance/entitlement-management-delegate'
        }
    },
    Azure: {
        key: 'Azure',
        name: 'Azure Resource Roles (Azure RBAC)',
        short: 'Azure',
        icon: 'azure',
        kind: 'roles',
        file: 'Classification/Classification_AzureResources.json',
        definition: EOCE.templateFile('Classification_Azure.json'),
        param: EOCE.templateFile('Classification_Azure.Param.json'),
        actionLabel: 'Resource action',
        description:
            'Azure built-in role definitions and their resource provider operations (Microsoft.*/*), classified against the Enterprise Access Model.',
        docs: 'https://learn.microsoft.com/azure/role-based-access-control/built-in-roles',
        // Some resource actions resolve to a different plane depending on whether the
        // role assignment scope targets privileged management groups/subscriptions -
        // see Classification_Azure.Param.json / the Scope-aware Tiering page.
        scopeAware: {
            label: 'Placeholder-based dynamic tiering',
            summary: 'Some Azure resource actions resolve to a different Enterprise Access Model plane depending on whether their role assignment scope targets privileged management groups or subscriptions. EntraOps resolves this dynamically from scope placeholders rather than from the resource action alone.',
            docsLabel: 'Scope-aware Tiering page',
            docs: '#scoped'
        }
    },
    DeviceManagement: {
        key: 'DeviceManagement',
        name: 'Intune Device Management Roles',
        short: 'Intune',
        icon: 'intune',
        kind: 'roles',
        file: 'Classification/Classification_DeviceManagementRoles.json',
        definition: EOCE.templateFile('Classification_DeviceManagement.json'),
        param: EOCE.templateFile('Classification_DeviceManagement.Param.json'),
        actionLabel: 'Role action',
        description:
            'Microsoft Intune (Device Management) RBAC roles and their Microsoft.Intune/* actions, classified against the Enterprise Access Model.',
        docs: 'https://learn.microsoft.com/mem/intune/fundamentals/role-based-access-control',
        // Some role actions resolve to a different plane depending on whether the
        // assignment scope targets privileged device/user groups - see
        // Classification_DeviceManagement.Param.json / the Scope-aware Tiering page.
        scopeAware: {
            label: 'Placeholder-based dynamic tiering',
            summary: 'Some Intune role actions resolve to a different Enterprise Access Model plane depending on whether their assignment scope targets privileged device or user groups. EntraOps resolves this dynamically from scope placeholders rather than from the role action alone.',
            docsLabel: 'Scope-aware Tiering page',
            docs: '#scoped'
        }
    },
    Defender: {
        key: 'Defender',
        name: 'Microsoft Defender XDR (Unified RBAC)',
        short: 'Defender',
        icon: 'defender',
        kind: 'definition',
        // Defender is classified from a tier definition (services -> microsoft.xdr/* actions),
        // not a per-role export, so it has no 'file'. Scope-aware Tier 0/1 resource tiering
        // lives in the separate .Param.json counterpart.
        definition: EOCE.templateFile('Classification_Defender.json'),
        param: EOCE.templateFile('Classification_Defender.Param.json'),
        actionLabel: 'Permission',
        description:
            'Microsoft Defender XDR unified RBAC permissions (microsoft.xdr/*), classified by service and scope against the Enterprise Access Model. Driven by the EntraOps Defender definition.',
        docs: 'https://learn.microsoft.com/defender-xdr/manage-rbac',
        scopeAware: {
            label: 'Placeholder-based dynamic tiering',
            summary: 'Some Defender XDR permissions resolve to a different Enterprise Access Model plane when their assignment scope targets a designated Tier 0 or Tier 1 resource scope. Assignments outside those configured scopes retain the base classification from the Defender definition.',
            docsLabel: 'Scope-aware Tiering page',
            docs: '#scoped'
        }
    }
};

// Keys of RBAC systems that have a per-role export ('roles' kind). Views that browse
// actual role objects iterate these; definition-only systems (e.g. Defender) are
// surfaced through derived role actions and scope-aware tiering instead.

// Display order for RBAC system filters / segments across every view.
EOCE.RBAC_ORDER = ['Azure', 'Defender', 'EntraID', 'IdentityGovernance', 'DeviceManagement'];

// All RBAC system keys in the configured display order (any key not listed in
// RBAC_ORDER is appended afterwards so nothing is silently dropped).
EOCE.orderedRbacKeys = function () {
    var ordered = EOCE.RBAC_ORDER.filter(function (k) { return EOCE.RBAC_SYSTEMS[k]; });
    Object.keys(EOCE.RBAC_SYSTEMS).forEach(function (k) {
        if (ordered.indexOf(k) === -1) ordered.push(k);
    });
    return ordered;
};

EOCE.rolesSystemKeys = function () {
    return EOCE.orderedRbacKeys().filter(function (k) {
        return EOCE.RBAC_SYSTEMS[k].kind === 'roles';
    });
};

// Role exports occasionally carry RolePermissions as a single object instead of an
// array (a role with exactly one permission). Always return an array so callers can
// iterate safely.
EOCE.rolePerms = function (role) {
    var p = role && role.RolePermissions;
    if (!p) return [];
    return Array.isArray(p) ? p : [p];
};

// Informational callout explaining a system's advanced scope-aware tiering. Used by
// the Roles and Role Actions views; returns '' for systems without scope-aware logic.
// References EOCE.util at call time (rendering happens after all scripts have loaded).
EOCE.scopeAwareCallout = function (sysKey) {
    var sys = EOCE.RBAC_SYSTEMS[sysKey];
    var sa = sys && sys.scopeAware;
    if (!sa) return '';
    var esc = EOCE.util.escapeHtml;
    var html = '<div class="callout scope" style="margin:0 0 16px;">' +
        '<div class="callout-title">Advanced scope-aware tiering &middot; ' + esc(sa.label) + '</div>' +
        esc(sa.summary);
    if (sa.methods && sa.methods.length) {
        html += '<div style="margin-top:10px;display:grid;gap:8px;">';
        sa.methods.forEach(function (m) {
            html += '<div><span class="chip cell-mono" style="font-size:11px;">TaggedBy: ' + esc(m.tag) + '</span> ' + esc(m.text) + '</div>';
        });
        html += '</div>';
    }
    if (sa.docs) {
        var linkLabel = esc(sa.docsLabel || 'Learn more');
        var isInternal = String(sa.docs).charAt(0) === '#';
        html += '<div style="margin-top:10px;"><a href="' + (isInternal ? esc(sa.docs) : EOCE.util.safeUrl(sa.docs)) +
            (isInternal ? '' : '" target="_blank" rel="noopener noreferrer') + '">' + linkLabel + ' &rarr;</a></div>';
    }
    html += '</div>';
    return html;
};

// Small inline badge marking a scope-aware row / entry. `aware` is the caller's
// precomputed per-role/per-action verdict (see EOCE.loadScopeAwareActions); when
// omitted, falls back to the system-wide flag (true for IdentityGovernance, whose
// entire delegation model is scope-aware - see EOCE.isFullyScopeAwareSystem).
EOCE.scopeAwareChip = function (sysKey, aware) {
    var sys = EOCE.RBAC_SYSTEMS[sysKey];
    if (!sys || !sys.scopeAware) return '';
    if (aware === undefined) aware = EOCE.isFullyScopeAwareSystem(sysKey);
    if (!aware) return '';
    return '<span class="chip scope" title="' + EOCE.util.escapeHtml(sys.scopeAware.summary) + '">scope-aware</span>';
};

// --- Scope-aware placeholder detection ------------------------------------
// The same role action can land on a different Enterprise Access Model plane
// depending on the scope it is assigned over. EntraOps expresses this with scope
// placeholders (e.g. <ScopeNamePrivilegedUsers>) in the *.Param.json / definition
// files of EntraID, Azure, DeviceManagement and Defender - see the Scope-aware
// Tiering page (js/views/scoped.js) for the per-service breakdown. Identity
// Governance uses a different mechanism (catalog-scoped delegation, see its
// scopeAware.allActionsScopeAware flag above) where every role/action is scope-aware
// regardless of any placeholder.
//
// The sanitizer in data.js turns <Token> into "«param:Token»" for *.Param.json files;
// Defender's un-sanitized definition file keeps quoted "<Token>" strings, so both
// forms are recognised here (mirrors js/views/scoped.js's PARAM_RE / RAW_PARAM_RE).
EOCE.SCOPE_PARAM_RE = /^«param:([A-Za-z0-9_]+)»$/;
EOCE.SCOPE_RAW_PARAM_RE = /^<([A-Za-z0-9_]+)>$/;

EOCE.scopeParamOf = function (arr) {
    if (!Array.isArray(arr)) return false;
    for (var i = 0; i < arr.length; i++) {
        if (typeof arr[i] === 'string' && (EOCE.SCOPE_PARAM_RE.test(arr[i]) || EOCE.SCOPE_RAW_PARAM_RE.test(arr[i]))) {
            return true;
        }
    }
    return false;
};

// Keys of RBAC systems whose Param/definition file carries scope placeholders.
EOCE.SCOPE_PARAM_SYSTEMS = ['EntraID', 'Azure', 'DeviceManagement', 'Defender', 'IdentityGovernance'];

// True when a system's classification is scope-aware for every role/action regardless
// of the specific action (currently only Identity Governance's catalog-scoped model).
EOCE.isFullyScopeAwareSystem = function (sysKey) {
    var sys = EOCE.RBAC_SYSTEMS[sysKey];
    return !!(sys && sys.scopeAware && sys.scopeAware.allActionsScopeAware);
};

// Wildcard-aware, case-insensitive match between two action strings, EITHER of which may
// contain '*' (e.g. a role granting "Microsoft.Compute/*", or a classified pattern like
// "Microsoft.Authorization/*/write"). Mirrors the PowerShell classification engine's own
// Test-EntraOpsAzureActionMatch (Export-EntraOpsClassificationAzureRoles.ps1) so this
// re-derivation agrees with how roles are actually classified server-side, instead of only
// recognising exact literal-string matches (which silently misses any role whose actions are
// expressed as a wildcard not spelled out verbatim in the Param file, e.g. Key Vault
// Certificates Officer's "Microsoft.KeyVault/vaults/certificates/*").
EOCE._actionRegexCache = Object.create(null);
EOCE._actionToRegex = function (lowerPattern) {
    // Compiled-wildcard cache: the same patterns are tested against thousands of actions in the
    // Roles / Role Actions views - recompiling a RegExp per pair dominated their render time.
    var cached = EOCE._actionRegexCache[lowerPattern];
    if (!cached) {
        var escaped = lowerPattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
        cached = EOCE._actionRegexCache[lowerPattern] = new RegExp('^' + escaped + '$');
    }
    return cached;
};
EOCE.actionMatch = function (a, b) {
    if (!a || !b) return false;
    if (a === b) return true;
    var la = String(a).toLowerCase(), lb = String(b).toLowerCase();
    if (la === lb) return true;
    if (lb.indexOf('*') !== -1 && EOCE._actionToRegex(lb).test(la)) return true;
    if (la.indexOf('*') !== -1 && EOCE._actionToRegex(la).test(lb)) return true;
    return false;
};

// Loads (once) the scope-aware action PATTERNS per RBAC system, keyed by
// sysKey -> [{ pattern, actionType }], for the placeholder-based systems
// (EOCE.SCOPE_PARAM_SYSTEMS). Used by the Roles / Role Actions views to determine, per role or
// per action, whether its classification actually depends on scope - unlike Identity
// Governance, only some actions within these systems are scope-aware. actionType defaults to
// "Action" (see Get-EntraOpsTierDefinitionActionType) - only Azure's Param file uses "DataAction",
// and control/management plane Actions and data plane DataActions are separate namespaces, so a
// pattern from one plane must never match an action from the other.
EOCE._scopeAwareActionsPromise = null;
EOCE.loadScopeAwareActions = function () {
    if (EOCE._scopeAwareActionsPromise) return EOCE._scopeAwareActionsPromise;
    var keys = EOCE.SCOPE_PARAM_SYSTEMS.filter(function (k) { return EOCE.RBAC_SYSTEMS[k] && EOCE.RBAC_SYSTEMS[k].param; });
    var paths = keys.map(function (k) { return EOCE.RBAC_SYSTEMS[k].param; });
    EOCE._scopeAwareActionsPromise = EOCE.data.loadAll(paths).then(function (params) {
        var bySystem = {};
        keys.forEach(function (sysKey, idx) {
            var patterns = [];
            (params[idx] || []).forEach(function (tierObj) {
                (tierObj.TierLevelDefinition || []).forEach(function (def) {
                    var scopeAware = EOCE.scopeParamOf(def.RoleAssignmentScopeName) || EOCE.scopeParamOf(def.ExcludedRoleAssignmentScopeName);
                    if (!scopeAware) return;
                    var actionType = def.ActionType === 'DataAction' ? 'DataAction' : 'Action';
                    (def.RoleDefinitionActions || []).forEach(function (a) { patterns.push({ pattern: a, actionType: actionType }); });
                });
            });
            bySystem[sysKey] = patterns;
            // Fast-match index attached to the array (consumers that iterate the array are
            // unaffected): exact patterns become a per-plane lowercase Set (EntraID and Intune
            // Param files contain no wildcards at all, so their matching collapses to Set.has);
            // wildcard patterns stay a small list matched via the cached-regex actionMatch.
            var index = { Action: { literalSet: new Set(), literals: [], wildcards: [] }, DataAction: { literalSet: new Set(), literals: [], wildcards: [] } };
            patterns.forEach(function (p) {
                var lower = String(p.pattern).toLowerCase();
                var bucket = index[p.actionType] || index.Action;
                if (lower.indexOf('*') === -1) { bucket.literalSet.add(lower); bucket.literals.push(lower); }
                else bucket.wildcards.push(p.pattern);
            });
            try { Object.defineProperty(patterns, '__index', { value: index, enumerable: false }); }
            catch (_) { patterns.__index = index; }
        });
        return bySystem;
    });
    return EOCE._scopeAwareActionsPromise;
};

// Fast per-entry scope-aware test using the __index built in loadScopeAwareActions, with the
// same semantics as scanning the pattern array via EOCE.actionMatch: exact (case-insensitive)
// match, pattern-side wildcards, and action-side wildcards against literal patterns. Results
// are memoized per (system, plane, action) - actions repeat massively across roles.
EOCE._scopeAwareEntryCache = new Map();
EOCE._entryIsScopeAware = function (sysKey, entry, patterns) {
    var index = patterns.__index;
    if (!index) {
        // Fallback: index-less array (defensive) - original linear scan.
        for (var j = 0; j < patterns.length; j++) {
            if (patterns[j].actionType === entry.actionType && EOCE.actionMatch(entry.action, patterns[j].pattern)) return true;
        }
        return false;
    }
    var lower = String(entry.action || '').toLowerCase();
    var cacheKey = sysKey + '\u0001' + entry.actionType + '\u0001' + lower;
    var cached = EOCE._scopeAwareEntryCache.get(cacheKey);
    if (cached !== undefined) return cached;
    var bucket = index[entry.actionType] || index.Action;
    var result = bucket.literalSet.has(lower);
    if (!result) {
        for (var w = 0; w < bucket.wildcards.length; w++) {
            if (EOCE.actionMatch(entry.action, bucket.wildcards[w])) { result = true; break; }
        }
    }
    if (!result && lower.indexOf('*') !== -1) {
        // Action-side wildcard (e.g. an Azure role granting Microsoft.KeyVault/vaults/certificates/*)
        // can match a literal pattern - mirror actionMatch's reverse direction.
        var actionRe = EOCE._actionToRegex(lower);
        for (var l = 0; l < bucket.literals.length; l++) {
            if (actionRe.test(bucket.literals[l])) { result = true; break; }
        }
    }
    EOCE._scopeAwareEntryCache.set(cacheKey, result);
    return result;
};

// Normalizes an actionList entry (plain action string, or { action, actionType }) to
// { action, actionType } with actionType defaulting to 'Action'.
EOCE._normalizeScopeAwareEntry = function (item) {
    if (item && typeof item === 'object') return { action: item.action, actionType: item.actionType === 'DataAction' ? 'DataAction' : 'Action' };
    return { action: item, actionType: 'Action' };
};

// Whether a role/action in the given system is scope-aware: fully scope-aware systems
// (Identity Governance) always are; placeholder-based systems are scope-aware only if at
// least one action in actionList wildcard-matches a scope-aware pattern of the same plane
// (Action/DataAction). actionList entries may be plain action strings or { action, actionType }.
EOCE.roleIsScopeAware = function (sysKey, actionList, scopeAwareActionsBySystem) {
    if (EOCE.isFullyScopeAwareSystem(sysKey)) return true;
    var patterns = scopeAwareActionsBySystem && scopeAwareActionsBySystem[sysKey];
    if (!patterns || !patterns.length) return false;
    for (var i = 0; i < actionList.length; i++) {
        var entry = EOCE._normalizeScopeAwareEntry(actionList[i]);
        if (EOCE._entryIsScopeAware(sysKey, entry, patterns)) return true;
    }
    return false;
};

// The specific action(s) in actionList that make this role scope-aware (for attribution in the
// UI - e.g. "Key Vault Data Access Administrator" is scope-aware because it grants
// Microsoft.Authorization/roleAssignments/write, not because of its Key Vault data actions).
// Returns [] for fully scope-aware systems (there every action is scope-aware by the catalog
// delegation model itself, not by a specific matched pattern) or when nothing matches.
EOCE.scopeAwareMatchesForRole = function (sysKey, actionList, scopeAwareActionsBySystem) {
    if (EOCE.isFullyScopeAwareSystem(sysKey)) return [];
    var patterns = scopeAwareActionsBySystem && scopeAwareActionsBySystem[sysKey];
    if (!patterns || !patterns.length) return [];
    var seen = {}, matches = [];
    actionList.forEach(function (item) {
        var entry = EOCE._normalizeScopeAwareEntry(item);
        if (EOCE._entryIsScopeAware(sysKey, entry, patterns)) {
            if (!seen[entry.action]) { seen[entry.action] = true; matches.push(entry.action); }
        }
    });
    return matches;
};

// --- Microsoft Learn documentation comparison ----------------------------
// Highlights the gap between the role definition exposed by Microsoft Graph
// (Classification_EntraIdDirectoryRoles.json - the definition shown throughout
// this app) and the public Microsoft Learn permissions reference
// (Classification_EntraIdDirectoryRolesFromMsftDocs.json). Only Microsoft Entra
// ID directory roles are covered by that reference, so only EntraID is compared.
EOCE.DOCS_COMPARE = {
    EntraID: {
        file: 'Classification/Classification_EntraIdDirectoryRolesFromMsftDocs.json',
        graphLabel: 'Microsoft Graph',
        docsLabel: 'Microsoft Learn',
        docsUrl: 'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference'
    }
};

EOCE.hasDocsCompare = function (sysKey) {
    return !!EOCE.DOCS_COMPARE[sysKey];
};

// --- Change history (git log, standalone mode only) ------------------------
// window.EOCE_HISTORY is generated by the standalone-mode generator run (git-log
// walk, skip with -SkipHistory), keyed by the same RBAC system / permission-set
// keys used throughout the app (EOCE.RBAC_SYSTEMS / EOCE.PERMISSION_SETS), so a
// role's sysKey or a permission's setKey doubles as its History source key. Used
// to surface a lightweight "recently changed" badge on the Roles, Role Actions
// and API Permissions views, linking through to the full History view. The
// History view/nav item is mode-gated to standalone (see js/app.js); these
// helpers additionally short-circuit in entraops mode so they never render
// stale badges even if a bundle happened to carry old history data.
EOCE.historySource = function (sourceKey) {
    if (EOCE.isEntraOpsMode()) return null;
    var h = window.EOCE_HISTORY;
    return (h && h.sources && h.sources[sourceKey]) || null;
};

EOCE.historyLatestCommit = function (sourceKey) {
    var src = EOCE.historySource(sourceKey);
    var commits = src && src.commits;
    return (commits && commits.length) ? commits[commits.length - 1] : null;
};

// { id -> 'added' | 'changed' } for the most recent commit of a source, or null
// when there is no recorded history for it.
EOCE.historyLatestItemStatus = function (sourceKey) {
    var c = EOCE.historyLatestCommit(sourceKey);
    if (!c) return null;
    var map = {};
    (c.added || []).forEach(function (i) { map[i.id] = 'added'; });
    (c.changed || []).forEach(function (i) { map[i.id] = 'changed'; });
    return map;
};

// Set of role-action strings touched (added or removed from some role) by the
// most recent commit of a 'roles' source - used by the Role Actions view, which
// has no stable per-action id of its own. Includes actions changed on an existing
// role as well as the full action list of a brand-new or removed role.
EOCE.historyLatestActionSet = function (sourceKey) {
    var c = EOCE.historyLatestCommit(sourceKey);
    if (!c) return null;
    var set = {};
    (c.added || []).forEach(function (i) { (i.actions || []).forEach(function (a) { set[a] = true; }); });
    (c.removed || []).forEach(function (i) { (i.actions || []).forEach(function (a) { set[a] = true; }); });
    (c.changed || []).forEach(function (i) {
        (i.actionsAdded || []).forEach(function (a) { set[a] = true; });
        (i.actionsRemoved || []).forEach(function (a) { set[a] = true; });
    });
    return set;
};

// Set of role-action strings that are genuinely NEW in the most recent commit of
// a 'roles' source - i.e. introduced by a brand-new role, or added to an existing
// role. Excludes removed actions (which are gone, but could still exist on another
// role) so the Role Actions view only shows the "new" badge for actually-new
// actions. Returns null when there is no recorded history for the source.
EOCE.historyLatestAddedActionSet = function (sourceKey) {
    var c = EOCE.historyLatestCommit(sourceKey);
    if (!c) return null;
    var set = {};
    (c.added || []).forEach(function (i) { (i.actions || []).forEach(function (a) { set[a] = true; }); });
    (c.changed || []).forEach(function (i) { (i.actionsAdded || []).forEach(function (a) { set[a] = true; }); });
    return set;
};

// Small inline badge marking a row that was added or changed in the most recent
// recorded commit for its source.
EOCE.historyChangedChip = function (status) {
    if (!status) return '';
    var label = status === 'added' ? 'new' : 'changed';
    return '<span class="chip diff-move" title="' + (status === 'added' ? 'Added' : 'Changed') +
        ' in the most recent recorded classification update">\u23F1 ' + label + '</span>';
};

// Toolbar link summarising the most recent recorded change for a source, or ''
// when there is no history recorded. sourceKey defaults to the RBAC system /
// permission-set key (they share the same keys as EOCE_HISTORY.sources).
EOCE.historyToolbarLink = function (sourceKey) {
    var c = EOCE.historyLatestCommit(sourceKey);
    if (!c) return '';
    var n = (c.added || []).length + (c.removed || []).length + (c.changed || []).length;
    if (!n) return '';
    return '<a class="chip hist-changed-badge" href="#history/' + encodeURIComponent(sourceKey) +
        '" title="Last classification update: ' + EOCE.util.escapeHtml(c.subject || '') + '">\u23F1 ' +
        EOCE.util.formatNumber(n) + ' change' + (n === 1 ? '' : 's') + ' in last update</a>';
};

// "View history" link for a single role / role action / permission, jumping straight
// to the History view with that item's name prefilled in the cross-commit search (see
// js/views/history.js renderSearchDetail) - shown in the Roles, Role Actions and API
// Permissions detail drawers. Returns '' when the source has no recorded history at all.
EOCE.historyItemLink = function (sourceKey, name, label) {
    if (!EOCE.historySource(sourceKey)) return '';
    return '<a class="inline-link" href="#history/' + encodeURIComponent(sourceKey) + '/find/' + encodeURIComponent(name) +
        '">\u23F1 ' + EOCE.util.escapeHtml(label || 'View change history') + ' &rarr;</a>';
};

// Build an index { RoleId: { name, actions: { loweredAction: originalAction } } }
// from a Microsoft Learn docs classification array, for fast per-role comparison.
EOCE.buildDocsIndex = function (docsArray) {
    var byId = {};
    (docsArray || []).forEach(function (role) {
        if (!role || !role.RoleId) return;
        var actions = {};
        EOCE.rolePerms(role).forEach(function (p) {
            var a = p && p.AuthorizedResourceAction;
            if (a) actions[String(a).toLowerCase()] = a;
        });
        byId[role.RoleId] = { name: role.RoleName, actions: actions };
    });
    return byId;
};

// Compare a Graph-sourced role against the Microsoft Learn docs index.
// Returns null when the system isn't covered or no docs index is available.
// onlyInGraph = actions in the live definition that are NOT documented on Learn.
// onlyInDocs  = actions documented on Learn that are NOT in the live definition.
EOCE.roleDocDiff = function (sysKey, role, docsIndex) {
    if (!docsIndex || !EOCE.hasDocsCompare(sysKey) || !role) return null;
    var graphActions = {};
    EOCE.rolePerms(role).forEach(function (p) {
        var a = p && p.AuthorizedResourceAction;
        if (a) graphActions[String(a).toLowerCase()] = a;
    });
    var docEntry = docsIndex[role.RoleId];
    if (!docEntry) {
        return { docRoleMissing: true, onlyInGraph: [], onlyInDocs: [], graphOnlyLower: {} };
    }
    var onlyInGraph = [], onlyInDocs = [], graphOnlyLower = {};
    Object.keys(graphActions).forEach(function (k) {
        if (!docEntry.actions[k]) { onlyInGraph.push(graphActions[k]); graphOnlyLower[k] = true; }
    });
    Object.keys(docEntry.actions).forEach(function (k) {
        if (!graphActions[k]) onlyInDocs.push(docEntry.actions[k]);
    });
    var sortFn = function (a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; };
    return {
        docRoleMissing: false,
        onlyInGraph: onlyInGraph.sort(sortFn),
        onlyInDocs: onlyInDocs.sort(sortFn),
        graphOnlyLower: graphOnlyLower
    };
};

// Total number of mismatching role actions for a diff.
EOCE.docMismatchCount = function (diff) {
    if (!diff || diff.docRoleMissing) return 0;
    return diff.onlyInGraph.length + diff.onlyInDocs.length;
};

// Small inline badge marking a role whose role actions differ from the docs.
EOCE.docMismatchChip = function (diff) {
    var count = EOCE.docMismatchCount(diff);
    if (!count) return '';
    return '<span class="chip docdiff" title="' + count + ' role action' + (count === 1 ? '' : 's') +
        ' differ between the Microsoft Graph role definition and the Microsoft Learn permissions reference">' +
        '\u21C4 doc mismatch</span>';
};

// Drawer callout summarising the documentation mismatch for a role.
EOCE.docMismatchCallout = function (sysKey, diff) {
    if (!diff) return '';
    var cfg = EOCE.DOCS_COMPARE[sysKey];
    if (!cfg) return '';
    var esc = EOCE.util.escapeHtml;
    if (diff.docRoleMissing) {
        return '<div class="callout docdiff" style="margin:14px 0;">' +
            '<div class="callout-title">\u21C4 Not in the ' + esc(cfg.docsLabel) + ' reference</div>' +
            'This role is not present in the ' + esc(cfg.docsLabel) +
            ' permissions reference, so its role actions could not be compared.' +
            '</div>';
    }
    var count = EOCE.docMismatchCount(diff);
    if (!count) return '';
    var html = '<div class="callout docdiff" style="margin:14px 0;">' +
        '<div class="callout-title">\u21C4 Role action documentation mismatch</div>' +
        '<strong>' + count + '</strong> role action' + (count === 1 ? '' : 's') +
        ' differ between the ' + esc(cfg.graphLabel) + ' role definition (shown here) and the ' +
        esc(cfg.docsLabel) + ' permissions reference.';
    if (diff.onlyInGraph.length) {
        html += '<div style="margin-top:8px;"><strong>' + diff.onlyInGraph.length +
            '</strong> only in ' + esc(cfg.graphLabel) +
            ' &mdash; present in the live role definition but not documented on ' + esc(cfg.docsLabel) + '.</div>';
    }
    if (diff.onlyInDocs.length) {
        html += '<div style="margin-top:4px;"><strong>' + diff.onlyInDocs.length +
            '</strong> only in ' + esc(cfg.docsLabel) +
            ' &mdash; documented on ' + esc(cfg.docsLabel) + ' but not in the ' + esc(cfg.graphLabel) + ' definition.</div>';
    }
    html += '<div style="margin-top:10px;"><a href="' + cfg.docsUrl + '" target="_blank" rel="noopener noreferrer" class="inline-link">' +
        esc(cfg.docsLabel) + ' permissions reference \u2197</a></div>';
    html += '</div>';
    return html;
};

// --- Known attack paths --------------------------------------------------
// A curated set of well-documented privilege-escalation / lateral-movement
// paths that run through classified roles and role actions. Each path lists the
// role actions (and, where useful, the roles) that enable it, a step-by-step
// escalation chain, and external write-ups. This data powers the Attack Paths
// view and tags any role / role action that participates in a path.
//
// Defensive intent: this surfaces *why* certain Control Plane actions are
// dangerous so defenders can prioritise monitoring, least privilege and
// scope-aware tiering. It is descriptive, not a how-to.
EOCE.parseAttackPathMarkdown = function (md) {
    var fmMatch = md.match(/^---\s*\n([\s\S]*?)\n---\s*\n?/);
    var fm = {}, body = md;
    if (fmMatch) {
        fmMatch[1].split(/\n/).forEach(function (line) {
            var i = line.indexOf(':'); if (i === -1) return;
            fm[line.slice(0, i).trim()] = line.slice(i + 1).trim();
        });
        body = md.slice(fmMatch[0].length);
    }
    var sections = {};
    body.split(/\n##\s+/).forEach(function (chunk, idx) {
        var c = idx === 0 ? chunk.replace(/^##\s+/, '') : chunk;
        var nl = c.indexOf('\n'); if (nl === -1) return;
        sections[c.slice(0, nl).trim().toLowerCase()] = c.slice(nl + 1).trim();
    });
    function lines(name) { return (sections[name] || '').split(/\n/).map(function (l) { return l.trim(); }).filter(Boolean); }
    function pipe(name) {
        return lines(name).map(function (l) {
            return l.replace(/^[-*]\s*/, '').split('|').map(function (x) { return x.trim(); });
        }).filter(function (parts) { return parts.length >= 2 && parts[0] && parts[1]; });
    }
    var p = {
        id: fm.id, name: fm.name, severity: fm.severity, targetTier: fm.targetTier,
        summary: sections.summary || '', prerequisite: sections.prerequisite || '',
        steps: lines('steps').map(function (l) { return l.replace(/^\d+\.\s*/, ''); }),
        mitigations: lines('mitigations').map(function (l) { return l.replace(/^[-*]\s*/, ''); }),
        detection: lines('detection').map(function (l) { return l.replace(/^[-*]\s*/, ''); }),
        actions: pipe('actions').map(function (a) { return { sys: a[0], action: a[1] }; }),
        roles: pipe('roles').map(function (r) { return { sys: r[0], name: r[1] }; }),
        // API permissions (App Roles / Scopes) that enable the path. Authored as
        //   <ResourceApp> | <PermissionValue> | <Application|Delegated>
        // e.g. "Microsoft Graph | RoleManagement.ReadWrite.Directory | Application".
        // Standalone mode only - the entraops-mode Attack Paths view / graph does not
        // surface API-permission participants (see EOCE.attackPathsForPermission).
        permissions: EOCE.isEntraOpsMode() ? [] : pipe('permissions').map(function (r) { return { app: r[0], value: r[1], type: r[2] || '' }; }),
        references: pipe('references').map(function (r) { return { title: r[0], url: r[1] }; })
    };
    if (fm.basedOn) { var basedOn = fm.basedOn.split('|'); p.basedOn = { name: basedOn[0].trim(), url: (basedOn[1] || '').trim() }; }
    return p;
};
// Authored as markdown in content/attack-paths/<id>.md and embedded into
// window.EOCE_ATTACK_PATHS_MD by the generator script (run after edits).
EOCE.refreshAttackPaths = function () {
    EOCE.ATTACK_PATHS = (window.EOCE_ATTACK_PATHS_MD || []).map(EOCE.parseAttackPathMarkdown).filter(function (p) { return p && p.id; });
    EOCE._attackIndex = null;
    return EOCE.ATTACK_PATHS;
};
EOCE.refreshAttackPaths();

// Lazy lookup indexes for attack paths, keyed by "sysKey|loweredValue".
EOCE._attackIndex = null;
EOCE.attackIndex = function () {
    if (EOCE._attackIndex) return EOCE._attackIndex;
    var byAction = {}, byRoleName = {}, byPermission = {};
    EOCE.ATTACK_PATHS.forEach(function (p) {
        (p.actions || []).forEach(function (a) {
            var k = a.sys + '|' + String(a.action).toLowerCase();
            (byAction[k] = byAction[k] || []).push(p.id);
        });
        (p.roles || []).forEach(function (r) {
            var k = r.sys + '|' + String(r.name).toLowerCase();
            (byRoleName[k] = byRoleName[k] || []).push(p.id);
        });
        // API permissions are matched by permission value (case-insensitive); the
        // path's declared type (Application/Delegated), when present, is kept so a
        // permission that exists as both an App Role and a Scope only matches the
        // intended one.
        (p.permissions || []).forEach(function (perm) {
            if (!perm.value) return;
            var k = String(perm.value).toLowerCase();
            (byPermission[k] = byPermission[k] || []).push({ id: p.id, type: perm.type, app: perm.app });
        });
    });
    EOCE._attackIndex = { byAction: byAction, byRoleName: byRoleName, byPermission: byPermission };
    return EOCE._attackIndex;
};

EOCE.attackPathById = function (id) {
    for (var i = 0; i < EOCE.ATTACK_PATHS.length; i++) {
        if (EOCE.ATTACK_PATHS[i].id === id) return EOCE.ATTACK_PATHS[i];
    }
    return null;
};

// Attack paths whose enabling role actions include a specific action.
EOCE.attackPathsForAction = function (sysKey, action) {
    var ids = EOCE.attackIndex().byAction[sysKey + '|' + String(action).toLowerCase()] || [];
    return ids.map(EOCE.attackPathById).filter(Boolean);
};

// Attack paths for a role: matched by role name OR because the role contains
// one of a path's enabling role actions.
EOCE.attackPathsForRole = function (sysKey, role) {
    var idx = EOCE.attackIndex();
    var found = {};
    var nameKey = sysKey + '|' + String(role && role.RoleName).toLowerCase();
    (idx.byRoleName[nameKey] || []).forEach(function (id) { found[id] = true; });
    EOCE.rolePerms(role).forEach(function (p) {
        (idx.byAction[sysKey + '|' + String(p.AuthorizedResourceAction).toLowerCase()] || []).forEach(function (id) { found[id] = true; });
    });
    return Object.keys(found).map(EOCE.attackPathById).filter(Boolean);
};

// Attack paths enabled by a specific API permission (App Role / Scope). Matched
// by permission value; if the attack path declared a permission type it must also
// match the given permission's type (so e.g. an Application permission does not
// match a path that targets the Delegated variant of the same value).
// Standalone mode only - the entraops-mode Attack Paths view / graph does not
// surface API-permission participants (see js/views/attackpaths.js).
EOCE.attackPathsForPermission = function (perm) {
    if (EOCE.isEntraOpsMode()) return [];
    if (!perm || !perm.value) return [];
    var list = EOCE.attackIndex().byPermission[String(perm.value).toLowerCase()] || [];
    var ptype = String(perm.type || '').toLowerCase();
    var found = {};
    list.forEach(function (e) {
        if (e.type && ptype && String(e.type).toLowerCase() !== ptype) return;
        found[e.id] = true;
    });
    return Object.keys(found).map(EOCE.attackPathById).filter(Boolean);
};

// Small inline badge marking a role / action that participates in attack path(s).
EOCE.attackPathChip = function (count, title) {
    if (!count) return '';
    var label = count === 1 ? 'attack path' : count + ' attack paths';
    return '<span class="chip attack" title="' + EOCE.util.escapeHtml(title || 'Referenced by a known attack path') + '">\u26A0 ' + label + '</span>';
};

// Drawer callout listing the attack paths a role / action participates in, each
// linking to the Attack Paths view. Returns '' when there are none.
EOCE.attackPathCallout = function (paths) {
    if (!paths || !paths.length) return '';
    var esc = EOCE.util.escapeHtml;
    var html = '<div class="callout attack" style="margin:14px 0;">' +
        '<div class="callout-title">\u26A0 Known attack path' + (paths.length === 1 ? '' : 's') + '</div>' +
        'Referenced by ' + paths.length + ' documented privilege-escalation path' + (paths.length === 1 ? '' : 's') + '. ' +
        'Treat this access as high-risk and prioritise least privilege, scoping and monitoring.' +
        '<div style="margin-top:10px;display:grid;gap:10px;">';
    paths.forEach(function (p) {
        html += '<div>' +
            '<a href="#attackpaths/' + encodeURIComponent(p.id) + '" class="cell-strong" style="font-size:13px;">' + esc(p.name) + '</a> ' +
            EOCE.util.tierBadge(p.targetTier, { short: true }) +
            '<div class="muted" style="font-size:12px;margin-top:3px;">' + esc(p.summary) + '</div>' +
            '</div>';
    });
    html += '</div></div>';
    return html;
};

// Permission catalogs (flat lists of individual permissions / scopes).
// A single source of truth: Classification_ApiPermissions.json already contains
// both application permissions (AppRoles -> "Roles") and delegated permissions
// (OAuth2 "Scopes"), distinguished by PermissionType. The API Permissions view
// filters between them with the "Roles" / "Scopes" segment.
EOCE.PERMISSION_SETS = {
    ApiPermissions: {
        key: 'ApiPermissions',
        name: 'API Permissions (1st-party Microsoft APIs)',
        short: 'API Permissions',
        file: 'Classification/Classification_ApiPermissions.json',
        idField: 'PermissionId',
        valueField: 'PermissionValue',
        typeField: 'PermissionType',
        appField: 'TargetAppDisplayName',
        description:
            'Application permissions (AppRoles) and delegated permissions (Scopes) across major first-party Microsoft APIs (Microsoft Graph, Defender, Intune, Governance Insights and more).',
        docs: 'https://learn.microsoft.com/graph/permissions-reference'
    }
};

EOCE.OVERWRITES_FILE = EOCE.templateFile('Classification_RoleDefinitionOverwrites.json');
// Built-in role action overwrites template (optional; at runtime EntraOps reads
// Classification_RoleActionOverwrites.json only from the tenant-specific folder).
// Used by the entraops-mode-only Customize Overwrites view.
EOCE.ACTION_OVERWRITES_FILE = EOCE.templateFile('Classification_RoleActionOverwrites.json');
// Built-in API permission overwrites template (optional; at runtime EntraOps reads
// Classification_ApiPermissionOverwrites.json only from the tenant-specific folder, and only
// for RbacSystem ResourceApps). Schema is aligned with Classification_ApiPermissions.json
// entries (PermissionValue/PermissionType/TargetAppId/Category) instead of the RoleDefinitionActions/
// scope-pattern shape used by Classification_RoleActionOverwrites.json.
// Used by the entraops-mode-only Customize Overwrites view.
EOCE.API_PERMISSION_OVERWRITES_FILE = EOCE.templateFile('Classification_ApiPermissionOverwrites.json');
EOCE.DEFENDER_FILE = EOCE.templateFile('Classification_Defender.json');

// Scope placeholders used by EntraOps for scope-aware / dynamic tiering.
// Each placeholder is resolved to real administrative units, resource scopes or
// group IDs in the customer tenant when EntraOps runs.
EOCE.SCOPE_PLACEHOLDERS = {
    // --- Microsoft Entra ID (administrative-unit / restricted scopes) ---
    '<ScopeNamePrivilegedUsers>': {
        system: 'EntraID',
        label: 'Privileged Users',
        description: 'Administrative units / scopes that contain privileged user accounts.'
    },
    '<ScopeNamePrivilegedServicePrincipals>': {
        system: 'EntraID',
        label: 'Privileged Service Principals',
        description: 'Scopes that contain privileged workload identities (service principals / applications).'
    },
    '<ScopeNamePrivilegedGroups>': {
        system: 'EntraID',
        label: 'Privileged Groups',
        description: 'Scopes that contain role-assignable / privileged groups.'
    },
    '<ScopeNamePrivilegedDevices>': {
        system: 'EntraID',
        label: 'Privileged Devices',
        description: 'Scopes that contain privileged / secured workstations and devices.'
    },
    // --- Azure resource RBAC (resource / management-group scopes) ---
    // Note: Tier0/Tier1IncludedResourceScope are also reused by Microsoft Defender (Classification_Defender.Param.json)
    // to scope microsoft.xdr/securityposture/* (Posture management) actions via Defender for Cloud subscription/
    // resource-group/resource scope sets. Tenant-wide configuration/authorization/dataops actions are not
    // resource-scopable and remain governed at directory scope '/' only.
    '<Tier0IncludedResourceScope>': {
        system: 'Azure',
        label: 'Tier 0 Resource Scope',
        description: 'Azure management groups, subscriptions or resources designated as Control Plane (Tier 0). Also reused by Defender for Cloud scoping of microsoft.xdr/securityposture/* actions.'
    },
    '<Tier1IncludedResourceScope>': {
        system: 'Azure',
        label: 'Tier 1 Resource Scope',
        description: 'Azure scopes designated as Management Plane (Tier 1). Also reused by Defender for Cloud scoping of microsoft.xdr/securityposture/* actions.'
    },
    // --- Microsoft Entra Identity Governance (Entitlement Management catalogs) ---
    // Unlike the placeholder-based systems above (a single fixed action set that shifts plane by
    // scope, anchored to a stable, customer-curated Tier 0 allow-list), every Identity Governance
    // catalog action is delegated per access-package catalog - and catalogs are dynamic objects a
    // delegated admin can create at any time, including between classification runs. EntraOps
    // (Get-EntraOpsIdGovScopeClassification) therefore classifies each catalog by inspecting what is
    // actually assigned inside it and fails safe: a catalog only leaves Control Plane once it is
    // AFFIRMATIVELY proven to be Management Plane or User Access - anything unresolved, unclassified,
    // or newly created stays Control Plane by default (same conservative posture used throughout that
    // function for unclassifiable groups, roles and resources). There is deliberately no
    // "Tier0IncludedIdGovScope": Tier 0 is the residual bucket, not a positive list, so
    // Tier0ExcludedIdGovScope is simply the union of the two lists below - not an independent input.
    '<Tier0ExcludedIdGovScope>': {
        system: 'IdentityGovernance',
        label: 'Catalogs excluded from Control Plane',
        description: 'The union of the Tier 1 and Tier 2 catalog lists below - the only catalogs carved out of the Control Plane default. Everything else (including unresolved or brand-new catalogs) stays Control Plane until affirmatively proven otherwise.'
    },
    '<Tier1IncludedIdGovScope>': {
        system: 'IdentityGovernance',
        label: 'Management Plane catalogs',
        description: 'Access-package catalogs affirmatively classified as Management Plane, because the most-privileged resource assigned inside them (a group, directory role, API permission or Azure resource) resolved to Management Plane.'
    },
    '<Tier2IncludedIdGovScope>': {
        system: 'IdentityGovernance',
        label: 'User Access catalogs',
        description: 'Access-package catalogs affirmatively classified as User Access, because every resource assigned inside them (or the absence of any assigned resource) resolved no higher than User Access.'
    },
    // --- Intune device management (assigned group IDs) ---
    '<Tier0IncludedGroupIds>': {
        system: 'DeviceManagement',
        label: 'Tier 0 Group IDs',
        description: 'Intune scope (group) assignments designated as Control Plane (Tier 0).'
    },
    '<Tier1IncludedGroupIds>': {
        system: 'DeviceManagement',
        label: 'Tier 1 Group IDs',
        description: 'Intune scope (group) assignments designated as Management Plane (Tier 1).'
    },
    // --- Microsoft Defender XDR resource-scoped tiering ---
    // Tier 0/1 reuse the Azure resource-scope placeholders above. Assignments outside those
    // configured scopes retain the base classification from Classification_Defender.json.
    // Note: only microsoft.xdr/securityposture/* (Posture management) actions are genuinely scopable per
    // Defender for Cloud subscription. Tenant-wide configuration/authorization/dataops actions are not
    // resource-scopable and remain governed at directory scope '/' only. Defender for Identity (MDI) scope
    // parameterization is not supported.
};

EOCE.DOCS = {
    enterpriseAccessModel:
        'https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model',
    securedWorkstations:
        'https://learn.microsoft.com/security/privileged-access-workstations/overview',
    hipSessionVideo:
        'https://www.hipconf.com/resources/defending-tier-0-taking-control-of-your-clouds-control-plane/',
    administrativeUnits:
        'https://learn.microsoft.com/entra/identity/role-based-access-control/administrative-units',
    entraOpsRepo: 'https://github.com/cloud-architekt/entraops',
    entraOpsTiering:
        'https://github.com/Cloud-Architekt/EntraOps/blob/main/docs/EnterpriseAccessModel.md',
    privilegedIamRepo: 'https://github.com/Cloud-Architekt/AzurePrivilegedIAM',
    blog: 'https://www.cloud-architekt.net/',
    disclosure: 'https://www.cloud-architekt.net/disclosure/',
    license: 'https://github.com/Cloud-Architekt/AzurePrivilegedIAM/blob/main/LICENSE'
};
