# EntraOps Access Path Map

A **static web app** with an **APM-style, force-directed graph** visualization of the
EntraOps **OpenGraph model** — combining the nodes and edges emitted by the
[BloodHound integration](https://github.com/Cloud-Architekt/EntraOps/tree/main/Integrations/BloodHound) with Azure RBAC graph data —
enriched with Enterprise Access Model classification, scope, device and identity-relationship
details, built entirely from your
[EntraOps](https://github.com/cloud-architekt/entraops) Privileged EAM export.

Part of **Privileged EAM Reporting** (see [`Reports/index.html`](../index.html)) and styled after the
Microsoft **Fluent UI / Azure Portal** design, matching the
[Classification Explorer](../ClassificationExplorer/README.md),
[EAM Dashboard](../EamDashboard/README.md),
[Tier Breach Analyzer](../TierBreachAnalyzer/README.md) and
[Privilege History](../PrivilegeHistory/README.md).

## What you can do

- **Graph model** — nodes and edges build on `Export-EntraOpsPrivilegedEAMBloodHound`:
  principals (`AZUser`/`AZGroup`/`AZServicePrincipal`/`AZDevice`), Entra ID role nodes (`AZRole`),
  EntraOps role/role-assignment nodes for Azure, Defender, Intune, Identity Governance and Resource Apps,
  administrative units and the tenant node. Relationship labels are shown APM-style
  (`HasRole`, `EligibleFor`, `HasAssignment`, `RoleAssigned`, `ClassifiedVia`, `ScopedTo`,
  `MemberOfAU`, `UsesPAW`, `PAWFor`, `OwnsDevice`, `DeviceOwner`, `OwnerOf`, `OwnedBy`,
  `HasWorkAccount`, `SponsoredBy`,
  `IdentityParent`, `DeviceAction`, `MemberOf`), and node kinds have their internal `AZ`/`EO_`
  prefix stripped for display everywhere in the UI (drawer, tables, CSV export) — the internal
  kind strings only exist to match the BloodHound OpenGraph model in the underlying dataset;
  the detail drawer keeps only the human-readable relationship/kind labels, no raw
  technical identifiers.

  Azure RBAC is included from `PrivilegedEAM/Azure/Azure.json`. Because the standalone BloodHound
  exporter does not currently process the `Azure` RBAC system, the Access Path Map generator adds
  the corresponding `EO_AzureRole`/`EO_AzureRoleAssignment` nodes and active, eligible, assignment,
  ownership and scope-reasoning edges directly to its graph dataset before the common enrichment
  and tier-breach pipeline runs.
- **Force-directed graph canvas** — drag to pan, scroll to zoom, drag nodes to rearrange, click a
  node or edge to open its full detail drawer and highlight the connected sub-graph. Right-click a
  node to open a context menu with quick actions ("Show full context in graph", "Open details",
  "Focus connections"). Nodes are
  color-coded by kind (users, groups, service principals, devices, roles, role assignments,
  administrative units, tenant) with an Enterprise Access Model tier ring (Control Plane /
  Management Plane / Workload Plane / User Access / Unclassified) around principal and role nodes.
- **Enrichment beyond roles** — the node/edge detail drawer surfaces every property from the
  OpenGraph payload: classification tiers/services, restricted management flags, sync source,
  scope (administrative unit / tenant-wide), PIM assignment type, transitive/nesting context,
  `TaggedBy`/`ClassifiedVia` provenance, device ownership, PAW assignment, work-account linking,
  sponsor and identity-parent relationships. Property names are shown in PascalCase
  (`RoleAssignmentScopeId`, `RestrictedManagementByAadRole`, ...) even though the underlying
  dataset stores them all-lowercase for OpenGraph/BloodHound compatibility — this is a
  display-only lookup and does not change the dataset.
- **Known tier-breach attack paths, like the Tier Breach Analyzer** — switch between *Tier 0 attack
  paths* (the headline case: a Tier 1 / Tier 2 principal reaching a Tier 0 / Control Plane
  service), *all tier breach paths* and the *full graph* from the left navigation. The same tiering
  rule applies: a principal without classification is treated as Tier 2 (User Access).
  Each principal &rarr; privilege path is counted once: a privilege is drawn both as a
  principal &rarr; role assignment edge and a principal &rarr; role edge, but the *Tier breach
  paths* / *Tier 0 attack paths* counts include only the role assignment edge (or the role edge
  when no role assignment node exists; such edges carry `distinctpath = true` in the dataset).
  *Roles reaching Tier 0* counts distinct role definitions only, not role assignments.
- **Known (documented) attack paths, cross-referenced with the Classification Explorer** — roles
  and role assignments are matched against the same curated attack-path catalog the Classification
  Explorer's *Attack Paths* view uses
  ([`content/attack-paths/*.md`](../ClassificationExplorer/content/attack-paths)) by role name or
  role action. Matches show a "&#9888; N attack paths" badge and a callout in the node/edge drawer
  linking straight to the full write-up, and an **"Only documented attack paths"** filter narrows
  any view down to just these. This is deliberately a *different, narrower* signal than "tier
  breach": a path can cross a tier boundary without being a documented technique, and vice versa.
- **Scope & classification provenance** — role assignment nodes list every *other* privileged
  object sharing the exact same RBAC scope ("Other privileged objects sharing this scope"), and any
  node reached via `EO_ClassifiedViaObject`/`EO_ScopedTo` shows who/what is classified through it.
  A **"Show full context in graph"** button in the node drawer expands the graph to include a
  node's complete local neighborhood (scope, classification provenance, devices, sponsors, ...)
  even when some of those edges don't match the active view or filters.
- **Filters, like the Tier Breach Analyzer** — RBAC systems, principal types, relationship
  categories (role assignments & eligibility, classification & scope, devices & PAW, identity
  relationships) and a free-text search across node names, roles and scopes.
- **Attack path edges table** — every breachable relationship (principal &#8594; role / role
  assignment) with principal/service tier badges, scope, RBAC system and PIM assignment type;
  click a row to focus the graph on that principal. CSV export for follow-up.
- **Review list / bookmarking** — star a role (including its scope) directly from the attack path
  table or from a role node's detail drawer to add it to the same cross-tool **Review list** used
  by the Classification Explorer, EAM Dashboard and Tier Breach Analyzer (shared via
  `localStorage`). Every starred item keeps a deep link that jumps back to the exact node/edge
  selection — the graph re-opens with that node focused and its drawer open.
- **Bookmarkable selections** — clicking any node or edge updates the page's URL hash
  (`#node=<id>` / `#edge=<source>||<kind>||<target>`), so the current selection can be bookmarked
  or shared and reopens the same focus/drawer on reload.

## How tiering is evaluated

Same rules as the [Tier Breach Analyzer](../TierBreachAnalyzer/README.md):

- A principal's designated tier comes from `ObjectAdminTierLevel`; unclassified principals are
  treated as **Tier 2 (User Access)**.
- A **tier breach** is an edge where the principal's tier is *less* privileged (higher tier number)
  than the tier of the role / service it can reach. A **Tier 0 attack path** is any Tier 1 / Tier 2
  principal reaching a Tier 0 (Control Plane) role.

## Run it

The app is fully self-contained: it ships a vendored copy of d3 and embeds its dataset as a script
file, so it works **offline from `file://`** — no web server, no internet connection, no backend.

1. Export your Privileged EAM data with the EntraOps module
   (`Save-EntraOpsPrivilegedEAMJson`), producing `PrivilegedEAM/<RbacSystem>/<RbacSystem>.json`.
2. Generate the dataset (internally calls `Export-EntraOpsPrivilegedEAMBloodHound` to build the
   canonical OpenGraph payload, then enriches it for standalone visualization):

   ```powershell
   Import-Module ./EntraOps -Force
   New-EntraOpsAccessPathMapData -TenantId "<tenant-id>"
   ```

3. Open `index.html` in a browser (double-click works), or serve the folder with any static web
   server / Azure Static Web Apps.

> [!WARNING]
> The generated `data/` bundle contains your tenant's privileged inventory (UPNs, object IDs,
> role assignments, PIM state) and its attack-path graph. Azure Static Web Apps — like most
> static hosts — serves every route **anonymously by default**. Do not publish this folder
> without putting authentication in front of it (e.g. `allowedRoles` in a
> `staticwebapp.config.json`, Entra ID authentication, or another access control).

To use a Privileged EAM export from another location, pass `-ImportPath`:

```powershell
New-EntraOpsAccessPathMapData -TenantId "<tenant-id>" -ImportPath "C:\Exports\PrivilegedEAM"
```

Use `Remove-EntraOpsReportingData` to clear the generated (tenant-specific) dataset again, or
`New-EntraOpsReportingData` to refresh all reporting apps in one call.

### Resolving object ids outside the Privileged EAM export

Some edges reference an object id that is not itself a privileged object in the Privileged EAM
export - e.g. a privileged account's standard, non-privileged work account
(`AssociatedWorkAccount`), an assigned PAW/SAW device, or a group/application/service principal
referenced via `OwnedObjects`/`Owners`/`Sponsors`. By default EntraOps resolves these objects in one
or more batched Microsoft Graph requests. Objects that cannot be returned remain explicit anonymous
"(unresolved object)" placeholder nodes, so their edges are still visible.

The behavior is managed through `AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM` in
`EntraOpsConfig.json` and can be overridden per invocation. EntraOps uses Microsoft Graph
(`POST /v1.0/directoryObjects/getByIds`) to resolve display names and object types:

```powershell
New-EntraOpsAccessPathMapData -TenantId "<tenant-id>" -ResolveObjectIdsOutsidePrivilegedEAM $true
```

Or via `EntraOpsConfig.json` (consumed by both `New-EntraOpsAccessPathMapData` and
`New-EntraOpsReportingData`):

```jsonc
"AccessPathMap": {
  "ResolveObjectIdsOutsidePrivilegedEAM": true
}
```

This requires an active Microsoft Graph connection (e.g. via `Connect-EntraOps` /
`Connect-MgGraph`) with at least directory read permissions (`User.Read.All`, `Group.Read.All`,
`Application.Read.All` or `Directory.Read.All`). The generator reports the lookup duration and
warns when it takes 30 seconds or longer. If this materially slows report generation, set the
option to `false`; affected endpoints remain unresolved placeholders and their edges stay visible.

In the automated `Push-EntraOpsPrivilegedReporting` workflow, this is controlled by the
`AccessPathMapResolveObjectIdsOutsidePrivilegedEAM` environment flag (populated from the config
setting above by `Update-EntraOpsRequiredWorkflowParameters`). When enabled, the "Generate Access
Path Map data" step connects via `Connect-EntraOps -AuthenticationType FederatedCredentials`
(same OIDC federated-credential sign-in used by `Push-EntraOpsPrivilegedEAM`, requiring a preceding
`azure/login` step and the `id-token: write` permission) and calls `Disconnect-EntraOps` again once
the dataset has been generated; when disabled, the step runs without any Graph connection, as before.

## Folder structure

```
AccessPathMap/
├── index.html                            App shell (portal-style app bar + navigation)
├── css/styles.css                        Fluent / Azure Portal design system + graph canvas styles
├── js/app.js                             Graph rendering, filters, drawer, deep links, CSV export
├── js/review.js                          Shared cross-tool Review list (bookmarking)
├── data/access-path-map-data.js   Generated dataset (window.ENTRAOPS_APM_DATA)
└── assets/                               Logo and vendored d3 library
```

The folder is independent by design: copy `Reports/AccessPathMap/` anywhere (together with
its generated `data/` bundle) and it keeps working. The "Privileged EAM Reporting" navigation links to
the landing page and the other apps only resolve inside the full repository layout.
